package queue

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// metrics are the queue's counters in this replica.
type metrics struct {
	claims         atomic.Int64
	claimNanos     atomic.Int64
	leaseLosses    atomic.Int64
	reaperRequeues atomic.Int64
}

func (m *metrics) leaseLost() {
	m.leaseLosses.Add(1)
}

func (m *metrics) claimed(took time.Duration) {
	m.claims.Add(1)
	m.claimNanos.Add(int64(took))
}

// Stats are the queue metrics (exposed by the metrics endpoint, P10-4). Depth
// and OldestQueuedAge are read from MongoDB and are the same on every replica;
// the others count what this replica did since it started.
type Stats struct {
	// Depth is the number of queued scans.
	Depth int64
	// OldestQueuedAge is how long the oldest queued scan has waited, on
	// MongoDB's clock; 0 when nothing is queued.
	OldestQueuedAge time.Duration
	// Claims and ClaimDuration are the number and total duration of claim calls
	// (claim latency = ClaimDuration / Claims).
	Claims        int64
	ClaimDuration time.Duration
	LeaseLosses   int64
	// ReaperRequeues counts scans the reaper put back in the queue.
	ReaperRequeues int64
}

// Stats returns the queue metrics.
func (q *Queue) Stats(ctx context.Context) (Stats, error) {
	stats := Stats{
		Claims:         q.metrics.claims.Load(),
		ClaimDuration:  time.Duration(q.metrics.claimNanos.Load()),
		LeaseLosses:    q.metrics.leaseLosses.Load(),
		ReaperRequeues: q.metrics.reaperRequeues.Load(),
	}

	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "state", Value: store.ScanQueued}}}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: nil},
			{Key: "depth", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "oldest", Value: bson.D{{Key: "$min", Value: "$queued_at"}}},
		}}},
		{{Key: "$project", Value: bson.D{
			{Key: "depth", Value: 1},
			{Key: "age_ms", Value: bson.D{{Key: "$subtract", Value: bson.A{"$$NOW", "$oldest"}}}},
		}}},
	}
	cursor, err := q.scans.Aggregate(ctx, pipeline)
	if err != nil {
		return Stats{}, fmt.Errorf("reading queue depth: %w", err)
	}
	defer cursor.Close(ctx)
	if !cursor.Next(ctx) {
		if err := cursor.Err(); err != nil {
			return Stats{}, fmt.Errorf("reading queue depth: %w", err)
		}
		return stats, nil // nothing queued
	}
	var row struct {
		Depth int64 `bson:"depth"`
		AgeMS int64 `bson:"age_ms"`
	}
	if err := cursor.Decode(&row); err != nil {
		return Stats{}, fmt.Errorf("reading queue depth: %w", err)
	}
	stats.Depth = row.Depth
	stats.OldestQueuedAge = max(time.Duration(row.AgeMS)*time.Millisecond, 0)
	return stats, nil
}
