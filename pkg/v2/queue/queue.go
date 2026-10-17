// Package queue runs scans as jobs stored in the scans collection (DEMAND
// section 9): one document per image tag, enqueued again for each new scan;
// claims and leases on MongoDB's clock, a reaper for lost workers, and the
// worker pool.
package queue

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

var (
	// ErrQueueFull is returned by Enqueue when SCANNER_QUEUE_MAX_LENGTH scans are
	// queued (429 with Retry-After).
	ErrQueueFull = errors.New("the scan queue is full")
	// ErrScanInProgress is returned by Enqueue when the tag is queued or scanning
	// for another digest, or for a scope that does not cover the request (409
	// scan_in_progress with Retry-After).
	ErrScanInProgress = errors.New("a scan of this image tag is in progress")
)

// Queue is the scan queue of one scanner replica.
type Queue struct {
	client *store.Client
	cfg    config.Config
	scans  *mongo.Collection
	// wake tells this replica's idle workers that a scan was enqueued.
	wake chan struct{}
	// metrics are updated by the queue and read by the metrics endpoint.
	metrics metrics
}

// New returns the queue of this replica.
func New(client *store.Client, cfg config.Config) *Queue {
	return &Queue{
		client: client,
		cfg:    cfg,
		scans:  client.Database().Collection(store.CollectionScans),
		wake:   make(chan struct{}, 1),
	}
}

// Covers reports whether scope has every platform and severity of request.
func Covers(scope, request store.ScanOptions) bool {
	for _, platform := range request.Platforms {
		if !slices.Contains(scope.Platforms, platform) {
			return false
		}
	}
	for _, severity := range request.Severity {
		if !slices.Contains(scope.Severity, severity) {
			return false
		}
	}
	return true
}

// union returns the values of a and b, sorted, each once.
func union(a, b []string) []string {
	values := append(slices.Clone(a), b...)
	slices.Sort(values)
	return slices.Compact(values)
}

// Enqueue queues a scan of the image tag (DEMAND section 9). The tag has one
// document (_id store.ScanID); it keeps its last result until a new scan
// succeeds. created is false when the running scan of the tag is returned.
//   - No document yet: it is inserted, queued.
//   - The tag is queued or scanning: for the same digest with a scope that
//     covers the request, that scan is returned; otherwise ErrScanInProgress.
//   - Otherwise the document is queued again with the request's fields. When
//     the last result is for the same digest, the scope is the union of the
//     result's and the request's platforms and severities; when the tag moved
//     to another digest, it is the request's.
//
// The caller sets the request fields, the image with its digest and the
// reference, and Options.
func (q *Queue) Enqueue(ctx context.Context, scan store.Scan) (store.Scan, bool, error) {
	scan.ID = store.ScanID(scan.Image)
	scan.State = store.ScanQueued
	scan.QueuedAt = time.Now()
	scan.Attempt = 0

	// A concurrent request can create or queue the document between our read and
	// our write; the write then does not apply and we decide again.
	for try := 0; try < 3; try++ {
		existing, err := q.findOne(ctx, bson.D{{Key: "_id", Value: scan.ID}})
		found := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.Scan{}, false, err
		}
		if found && (existing.State == store.ScanQueued || existing.State == store.ScanScanning) {
			if existing.Image.Digest == scan.Image.Digest && Covers(existing.Options, scan.Options) {
				return existing, false, nil
			}
			return store.Scan{}, false, ErrScanInProgress
		}

		queued, err := q.queuedCount(ctx)
		if err != nil {
			return store.Scan{}, false, err
		}
		if queued >= int64(q.cfg.QueueMaxLength) {
			return store.Scan{}, false, ErrQueueFull
		}

		if !found {
			opCtx, cancel := q.client.OperationContext(ctx)
			_, err = q.scans.InsertOne(opCtx, scan)
			cancel()
			if mongo.IsDuplicateKeyError(err) {
				continue
			}
			if err != nil {
				return store.Scan{}, false, fmt.Errorf("enqueueing scan %s: %w", scan.ID, err)
			}
			q.wakeWorker()
			return scan, true, nil
		}

		requeued, err := q.requeue(ctx, scan, existing)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return store.Scan{}, false, err
		}
		q.wakeWorker()
		return requeued, true, nil
	}
	return store.Scan{}, false, fmt.Errorf("enqueueing scan %s: the document kept changing", scan.ID)
}

// requeue queues the tag's finished document again, unless another request did
// it first (store.ErrNotFound). The last result stays in place.
func (q *Queue) requeue(ctx context.Context, scan store.Scan, existing store.Scan) (store.Scan, error) {
	scope := scan.Options
	if existing.Result != nil && existing.Result.Digest == scan.Image.Digest {
		scope.Platforms = union(existing.Result.Platforms, scan.Options.Platforms)
		scope.Severity = union(existing.Result.Severity, scan.Options.Severity)
	}
	set := bson.D{
		{Key: "state", Value: store.ScanQueued},
		{Key: "queued_at", Value: scan.QueuedAt},
		{Key: "attempt", Value: 0},
		{Key: "image", Value: scan.Image},
		{Key: "options", Value: scope},
		{Key: "reference", Value: scan.Reference},
		{Key: "requested_at", Value: scan.RequestedAt},
		{Key: "received_at", Value: scan.ReceivedAt},
		{Key: "customer_ids", Value: scan.CustomerIDs},
		{Key: "queue_wait_ms", Value: 0},
		{Key: "scan_ms", Value: 0},
		{Key: "total_ms", Value: 0},
	}
	unset := bson.D{}
	for _, field := range []string{"worker", "lease_until", "started_at", "finished_at", "error", "failure_class"} {
		unset = append(unset, bson.E{Key: field, Value: ""})
	}
	if scan.CustomerData != nil {
		set = append(set, bson.E{Key: "customer_data", Value: scan.CustomerData})
	} else {
		unset = append(unset, bson.E{Key: "customer_data", Value: ""})
	}
	if scan.LastRequestID != "" {
		set = append(set, bson.E{Key: "last_request_id", Value: scan.LastRequestID})
	} else {
		unset = append(unset, bson.E{Key: "last_request_id", Value: ""})
	}

	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	filter := bson.D{
		{Key: "_id", Value: scan.ID},
		{Key: "state", Value: bson.D{{Key: "$nin", Value: bson.A{store.ScanQueued, store.ScanScanning}}}},
	}
	update := bson.D{{Key: "$set", Value: set}, {Key: "$unset", Value: unset}}
	var requeued store.Scan
	err := q.scans.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&requeued)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return store.Scan{}, store.ErrNotFound
	}
	if err != nil {
		return store.Scan{}, fmt.Errorf("enqueueing scan %s: %w", scan.ID, err)
	}
	return requeued, nil
}

// wakeWorker wakes an idle worker of this replica; others find the scan when they poll.
func (q *Queue) wakeWorker() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *Queue) findOne(ctx context.Context, filter bson.D) (store.Scan, error) {
	return q.findOneWith(ctx, filter, options.FindOne())
}

func (q *Queue) findOneWith(ctx context.Context, filter bson.D, opts *options.FindOneOptionsBuilder) (store.Scan, error) {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	var scan store.Scan
	err := q.scans.FindOne(ctx, filter, opts).Decode(&scan)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return store.Scan{}, store.ErrNotFound
	}
	if err != nil {
		return store.Scan{}, fmt.Errorf("reading scan: %w", err)
	}
	return scan, nil
}

func (q *Queue) queuedCount(ctx context.Context) (int64, error) {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	count, err := q.scans.CountDocuments(ctx, bson.D{{Key: "state", Value: store.ScanQueued}})
	if err != nil {
		return 0, fmt.Errorf("counting queued scans: %w", err)
	}
	return count, nil
}
