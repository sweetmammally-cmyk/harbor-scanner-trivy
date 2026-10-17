//go:build integration

package queue

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestStats(t *testing.T) {
	ctx := context.Background()
	q, client, _ := newQueue(t, shortLease)

	stats, err := q.Stats(ctx)
	require.NoError(t, err)
	assert.Zero(t, stats.Depth, "nothing queued")
	assert.Zero(t, stats.OldestQueuedAge)

	first, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
	require.NoError(t, err)
	_, _, err = q.Enqueue(ctx, newScan("", "sha256:b"))
	require.NoError(t, err)
	// The oldest scan waited ten minutes; its age is measured on MongoDB's clock.
	setFields(t, client, first.ID, bson.M{"$set": bson.M{"queued_at": time.Now().Add(-10 * time.Minute)}})

	stats, err = q.Stats(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, stats.Depth)
	assert.InDelta(t, (10 * time.Minute).Seconds(), stats.OldestQueuedAge.Seconds(), 5)

	// A claim of the oldest scan: one claim timed, depth down to one.
	claimed, err := q.Claim(ctx, "replica-1/worker-0")
	require.NoError(t, err)
	assert.Equal(t, first.ID, claimed.ID)
	stats, err = q.Stats(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, stats.Depth)
	assert.Less(t, stats.OldestQueuedAge, time.Minute)
	assert.EqualValues(t, 1, stats.Claims)
	assert.Positive(t, stats.ClaimDuration)

	// The lease expires and the reaper requeues the scan. (Lease losses are counted by the pool, see TestPool.)
	time.Sleep(300 * time.Millisecond)
	requeued, _, err := q.Reap(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, requeued)
	stats, err = q.Stats(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, stats.Depth)
	assert.EqualValues(t, 1, stats.ReaperRequeues)
}
