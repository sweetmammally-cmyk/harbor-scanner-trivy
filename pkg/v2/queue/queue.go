// Package queue runs scans as jobs stored in the scans collection (DEMAND
// section 9): enqueue with dedupe and idempotency, claims and leases on
// MongoDB's clock, a reaper for lost workers, and the worker pool.
package queue

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// ErrQueueFull is returned by Enqueue when SCANNER_QUEUE_MAX_LENGTH scans are
// queued (429 with Retry-After).
var ErrQueueFull = errors.New("the scan queue is full")

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

// ActiveKey identifies identical work: the same digest scanned for the same
// platforms and severities, on the same scan platform, with the same Trivy
// version. While a scan with this key is queued or scanning, a request for the
// same work gets that scan instead of a new one.
func ActiveKey(scan store.Scan) string {
	platforms := slices.Clone(scan.Options.Platforms)
	slices.Sort(platforms)
	severities := slices.Clone(scan.Options.Severity)
	slices.Sort(severities)
	key := strings.Join([]string{
		scan.Image.Digest,
		strings.Join(platforms, ","),
		strings.Join(severities, ","),
		scan.ScannedPlatform,
		scan.Trivy.Version,
	}, "\n")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
}

// Enqueue queues a new scan, or returns the existing scan for the same work.
// created is false when an existing scan was returned:
//   - a scan with the same request_id (queued, scanning or done; a failed scan
//     gave up its request_id, so a retry creates a new scan);
//   - a queued or scanning scan with the same ActiveKey.
//
// The caller sets ID, the request fields, the image with its digest and
// reference, Options, ScannedPlatform and Trivy.Version.
func (q *Queue) Enqueue(ctx context.Context, scan store.Scan) (store.Scan, bool, error) {
	scan.ActiveKey = ActiveKey(scan)
	scan.State = store.ScanQueued
	scan.QueuedAt = time.Now()
	scan.Attempt = 0

	if scan.RequestID != "" {
		existing, err := q.findOne(ctx, bson.D{{Key: "request_id", Value: scan.RequestID}})
		if err == nil || !errors.Is(err, store.ErrNotFound) {
			return existing, false, err
		}
	}
	existing, err := q.findOne(ctx, bson.D{{Key: "active_key", Value: scan.ActiveKey}})
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return existing, false, err
	}

	queued, err := q.queuedCount(ctx)
	if err != nil {
		return store.Scan{}, false, err
	}
	if queued >= int64(q.cfg.QueueMaxLength) {
		return store.Scan{}, false, ErrQueueFull
	}

	opCtx, cancel := q.client.OperationContext(ctx)
	_, err = q.scans.InsertOne(opCtx, scan)
	cancel()
	if mongo.IsDuplicateKeyError(err) {
		// Another request for the same work won the race: return its scan.
		filter := bson.D{{Key: "active_key", Value: scan.ActiveKey}}
		if strings.Contains(err.Error(), "request_id_unique") {
			filter = bson.D{{Key: "request_id", Value: scan.RequestID}}
		}
		existing, err = q.findOne(ctx, filter)
		return existing, false, err
	}
	if err != nil {
		return store.Scan{}, false, fmt.Errorf("enqueueing scan %s: %w", scan.ID, err)
	}

	// Wake an idle worker of this replica; others find the scan when they poll.
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return scan, true, nil
}

func (q *Queue) findOne(ctx context.Context, filter bson.D) (store.Scan, error) {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	var scan store.Scan
	err := q.scans.FindOne(ctx, filter).Decode(&scan)
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
