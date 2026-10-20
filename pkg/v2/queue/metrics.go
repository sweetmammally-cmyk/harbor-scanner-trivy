package queue

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// RecentWindow is how many of this replica's last scans Recent covers.
const RecentWindow = 20

// statsCacheTTL is how long CachedStats reuses a Stats result, so health checks
// and metric scrapes do not query MongoDB each time.
const statsCacheTTL = 10 * time.Second

// counters are the queue's counters in this replica.
type counters struct {
	claims         atomic.Int64
	claimNanos     atomic.Int64
	leaseLosses    atomic.Int64
	reaperRequeues atomic.Int64

	// recent holds the outcome of this replica's last scans (true = failed).
	recentMu sync.Mutex
	recent   []bool
}

// Recent counts the outcomes of this replica's last RecentWindow scans.
type Recent struct {
	Done   int
	Failed int
}

func (m *counters) scanFinished(failed bool) {
	m.recentMu.Lock()
	defer m.recentMu.Unlock()
	m.recent = append(m.recent, failed)
	if len(m.recent) > RecentWindow {
		m.recent = m.recent[1:]
	}
}

// Recent returns the outcomes of this replica's last RecentWindow scans.
func (q *Queue) Recent() Recent {
	q.metrics.recentMu.Lock()
	defer q.metrics.recentMu.Unlock()
	var recent Recent
	for _, failed := range q.metrics.recent {
		if failed {
			recent.Failed++
		} else {
			recent.Done++
		}
	}
	return recent
}

// PeekStats returns the last CachedStats result with the counters of now,
// without querying MongoDB (for metric scrapes); false before the first one.
func (q *Queue) PeekStats() (Stats, bool) {
	q.statsMu.Lock()
	defer q.statsMu.Unlock()
	stats := q.stats
	stats.Claims = q.metrics.claims.Load()
	stats.ClaimDuration = time.Duration(q.metrics.claimNanos.Load())
	stats.LeaseLosses = q.metrics.leaseLosses.Load()
	stats.ReaperRequeues = q.metrics.reaperRequeues.Load()
	return stats, !q.statsAt.IsZero()
}

// CachedStats is Stats, reused for statsCacheTTL.
func (q *Queue) CachedStats(ctx context.Context) (Stats, error) {
	q.statsMu.Lock()
	defer q.statsMu.Unlock()
	if !q.statsAt.IsZero() && time.Since(q.statsAt) < statsCacheTTL {
		return q.stats, nil
	}
	stats, err := q.Stats(ctx)
	if err != nil {
		return Stats{}, err
	}
	q.stats = stats
	q.statsAt = time.Now()
	return stats, nil
}

func (m *counters) leaseLost() {
	m.leaseLosses.Add(1)
}

func (m *counters) claimed(took time.Duration) {
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
	defer func() { _ = cursor.Close(ctx) }()
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
