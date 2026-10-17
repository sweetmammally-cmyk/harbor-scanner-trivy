package queue

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// ReapInterval is how often every replica runs the reaper.
const ReapInterval = 30 * time.Second

// FailureWorkerLost is the class of a scan whose workers kept losing its lease.
const FailureWorkerLost = "worker_lost"

// Reap recovers scans whose lease expired on MongoDB's clock (their worker died
// or lost MongoDB): a scan that has used SCANNER_QUEUE_MAX_ATTEMPTS claims fails
// with worker_lost, the others go back to the queue. It returns how many scans
// were requeued and failed.
func (q *Queue) Reap(ctx context.Context) (int64, int64, error) {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	expired := bson.E{Key: "$expr", Value: bson.D{{Key: "$lt", Value: bson.A{"$lease_until", "$$NOW"}}}}

	failed, err := q.scans.UpdateMany(ctx,
		bson.D{
			{Key: "state", Value: store.ScanScanning},
			{Key: "attempt", Value: bson.D{{Key: "$gte", Value: q.cfg.QueueMaxAttempts}}},
			expired,
		},
		mongo.Pipeline{
			{{Key: "$set", Value: bson.D{
				{Key: "state", Value: store.ScanFailed},
				{Key: "failure_class", Value: FailureWorkerLost},
				{Key: "error", Value: literal(fmt.Sprintf("the scan's worker stopped %d times (lease expired)", q.cfg.QueueMaxAttempts))},
				{Key: "finished_at", Value: "$$NOW"},
				{Key: "total_ms", Value: bson.D{{Key: "$subtract", Value: bson.A{"$$NOW", "$queued_at"}}}},
			}}},
			{{Key: "$unset", Value: bson.A{"lease_until"}}},
		})
	if err != nil {
		return 0, 0, fmt.Errorf("failing scans of lost workers: %w", err)
	}

	requeued, err := q.scans.UpdateMany(ctx,
		bson.D{
			{Key: "state", Value: store.ScanScanning},
			{Key: "attempt", Value: bson.D{{Key: "$lt", Value: q.cfg.QueueMaxAttempts}}},
			expired,
		},
		mongo.Pipeline{
			{{Key: "$set", Value: bson.D{{Key: "state", Value: store.ScanQueued}}}},
			{{Key: "$unset", Value: bson.A{"worker", "lease_until", "started_at"}}},
		})
	if err != nil {
		return 0, failed.ModifiedCount, fmt.Errorf("requeueing scans of lost workers: %w", err)
	}

	q.metrics.reaperRequeues.Add(requeued.ModifiedCount)
	if requeued.ModifiedCount > 0 || failed.ModifiedCount > 0 {
		slog.Warn("reaper recovered scans of lost workers",
			slog.Int64("requeued", requeued.ModifiedCount), slog.Int64("failed", failed.ModifiedCount))
	}
	return requeued.ModifiedCount, failed.ModifiedCount, nil
}

// RunReaper runs Reap every interval (ReapInterval in production) until ctx
// ends. It skips rounds while MongoDB is not ready.
func (q *Queue) RunReaper(ctx context.Context, interval time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		if !q.client.Ready() {
			continue
		}
		if _, _, err := q.Reap(ctx); err != nil {
			slog.Error("reaper failed", slog.String("error", err.Error()))
		}
	}
}
