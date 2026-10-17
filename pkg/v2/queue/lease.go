package queue

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

var (
	// ErrNoJob is returned by Claim when no scan is queued.
	ErrNoJob = errors.New("no queued scan")
	// ErrLeaseLost is returned by a worker write that no longer matches the scan:
	// another worker has it now, or it was requeued or failed. The worker must
	// discard its result.
	ErrLeaseLost = errors.New("the scan's lease was lost")
)

// All times of the lease come from MongoDB ($$NOW in pipeline updates), never
// from a replica's clock. Values we write go inside $literal, because a pipeline
// reads any string starting with "$" as a field path.

// Claim takes the oldest queued scan for worker: state scanning, the worker,
// attempt + 1, started_at and lease_until on MongoDB's clock. It returns
// ErrNoJob when no scan is queued.
func (q *Queue) Claim(ctx context.Context, worker string) (store.Scan, error) {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	update := mongo.Pipeline{{{Key: "$set", Value: bson.D{
		{Key: "state", Value: store.ScanScanning},
		{Key: "worker", Value: literal(worker)},
		{Key: "attempt", Value: bson.D{{Key: "$add", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$attempt", 0}}}, 1}}}},
		{Key: "started_at", Value: "$$NOW"},
		{Key: "lease_until", Value: q.leaseUntil()},
	}}}}
	opts := options.FindOneAndUpdate().SetSort(bson.D{{Key: "queued_at", Value: 1}}).SetReturnDocument(options.After)
	var scan store.Scan
	err := q.scans.FindOneAndUpdate(ctx, bson.D{{Key: "state", Value: store.ScanQueued}}, update, opts).Decode(&scan)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return store.Scan{}, ErrNoJob
	}
	if err != nil {
		return store.Scan{}, fmt.Errorf("claiming a scan: %w", err)
	}
	return scan, nil
}

// Heartbeat extends the lease of a claimed scan. ErrLeaseLost means the worker
// no longer owns the scan.
func (q *Queue) Heartbeat(ctx context.Context, scan store.Scan) error {
	return q.fencedUpdate(ctx, scan, mongo.Pipeline{{{Key: "$set", Value: bson.D{
		{Key: "lease_until", Value: q.leaseUntil()},
	}}}})
}

// Complete stores the result of a claimed scan (filled in by the scan runner,
// with its report or GridFS id) and marks it done. The active_key is removed,
// so the same work can be queued again. ErrLeaseLost means the result must be
// discarded.
func (q *Queue) Complete(ctx context.Context, scan store.Scan) error {
	set := bson.D{
		{Key: "state", Value: store.ScanDone},
		{Key: "finished_at", Value: "$$NOW"},
		{Key: "trivy", Value: literal(scan.Trivy)},
		{Key: "scanned_platform", Value: literal(scan.ScannedPlatform)},
		{Key: "platforms", Value: literal(scan.Platforms)},
		{Key: "platforms_found", Value: literal(scan.PlatformsFound)},
		{Key: "platforms_not_found", Value: literal(scan.PlatformsNotFound)},
		{Key: "has_more_platforms", Value: literal(scan.HasMorePlatforms)},
		{Key: "summary", Value: literal(scan.Summary)},
		{Key: "truncated", Value: literal(scan.Truncated)},
		{Key: "scan_ms", Value: literal(scan.ScanMS)},
		{Key: "queue_wait_ms", Value: bson.D{{Key: "$subtract", Value: bson.A{"$started_at", "$queued_at"}}}},
		{Key: "total_ms", Value: bson.D{{Key: "$subtract", Value: bson.A{"$$NOW", "$queued_at"}}}},
	}
	unset := bson.A{"active_key", "lease_until"}
	if scan.ReportGridFSID != nil {
		set = append(set, bson.E{Key: "report_gridfs_id", Value: literal(*scan.ReportGridFSID)})
		unset = append(unset, "report")
	} else {
		set = append(set, bson.E{Key: "report", Value: literal(scan.Report)})
		unset = append(unset, "report_gridfs_id")
	}
	return q.fencedUpdate(ctx, scan, mongo.Pipeline{
		{{Key: "$set", Value: set}},
		{{Key: "$unset", Value: unset}},
	})
}

// Fail marks a claimed scan failed with its failure class. Its request_id moves
// to prior_request_id, so a retry with the same request_id creates a new scan.
func (q *Queue) Fail(ctx context.Context, scan store.Scan, class, detail string) error {
	return q.fencedUpdate(ctx, scan, mongo.Pipeline{
		{{Key: "$set", Value: bson.D{
			{Key: "state", Value: store.ScanFailed},
			{Key: "failure_class", Value: literal(class)},
			{Key: "error", Value: literal(detail)},
			{Key: "finished_at", Value: "$$NOW"},
			{Key: "scan_ms", Value: literal(scan.ScanMS)},
			{Key: "total_ms", Value: bson.D{{Key: "$subtract", Value: bson.A{"$$NOW", "$queued_at"}}}},
			{Key: "prior_request_id", Value: "$request_id"},
		}}},
		{{Key: "$unset", Value: bson.A{"request_id", "active_key", "lease_until"}}},
	})
}

// Release puts a claimed scan back in the queue at once, without counting the
// attempt: the worker is shutting down, it did not fail.
func (q *Queue) Release(ctx context.Context, scan store.Scan) error {
	return q.fencedUpdate(ctx, scan, mongo.Pipeline{
		{{Key: "$set", Value: bson.D{
			{Key: "state", Value: store.ScanQueued},
			{Key: "attempt", Value: bson.D{{Key: "$subtract", Value: bson.A{"$attempt", 1}}}},
		}}},
		{{Key: "$unset", Value: bson.A{"worker", "lease_until", "started_at"}}},
	})
}

// fencedUpdate applies update only while the worker still owns the scan: same
// _id, worker and attempt, still scanning.
func (q *Queue) fencedUpdate(ctx context.Context, scan store.Scan, update mongo.Pipeline) error {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	filter := bson.D{
		{Key: "_id", Value: scan.ID},
		{Key: "worker", Value: scan.Worker},
		{Key: "attempt", Value: scan.Attempt},
		{Key: "state", Value: store.ScanScanning},
	}
	result, err := q.scans.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("updating scan %s: %w", scan.ID, err)
	}
	if result.MatchedCount == 0 {
		return ErrLeaseLost
	}
	return nil
}

// leaseUntil is $$NOW plus the lease, as a pipeline expression.
func (q *Queue) leaseUntil() bson.D {
	return bson.D{{Key: "$add", Value: bson.A{"$$NOW", q.cfg.QueueLease.Milliseconds()}}}
}

func literal(value any) bson.D {
	return bson.D{{Key: "$literal", Value: value}}
}
