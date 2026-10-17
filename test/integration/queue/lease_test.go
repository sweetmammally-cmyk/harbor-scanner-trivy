//go:build integration

package queue

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/mongotest"
)

// mongoNow reads MongoDB's clock.
func mongoNow(t *testing.T, client *store.Client) time.Time {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	var result struct {
		LocalTime time.Time `bson:"localTime"`
	}
	require.NoError(t, client.Database().RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&result))
	return result.LocalTime
}

func TestClaim(t *testing.T) {
	ctx := context.Background()

	t.Run("each queued scan is claimed exactly once by several replicas", func(t *testing.T) {
		first, _, cfg := newQueue(t, nil)
		for i := 0; i < 40; i++ {
			_, _, err := first.Enqueue(ctx, newScan("", fmt.Sprintf("sha256:%d", i)))
			require.NoError(t, err)
		}
		replicas := []*queue.Queue{first}
		for i := 0; i < 3; i++ {
			replicas = append(replicas, queue.New(mongotest.Client(t, cfg), cfg))
		}

		var mu sync.Mutex
		claimed := map[string]int{}
		var wg sync.WaitGroup
		for r, replica := range replicas {
			for w := 0; w < 4; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						scan, err := replica.Claim(ctx, fmt.Sprintf("replica-%d/worker-%d", r, w))
						if err == queue.ErrNoJob {
							return
						}
						if !assert.NoError(t, err) {
							return
						}
						mu.Lock()
						claimed[scan.ID]++
						mu.Unlock()
					}
				}()
			}
		}
		wg.Wait()

		assert.Len(t, claimed, 40)
		for id, count := range claimed {
			assert.Equal(t, 1, count, id)
		}
	})

	t.Run("the oldest queued scan first, with a lease on MongoDB's clock", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		older, _, err := q.Enqueue(ctx, newScan("", "sha256:older"))
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond) // queued_at has millisecond precision
		_, _, err = q.Enqueue(ctx, newScan("", "sha256:newer"))
		require.NoError(t, err)

		before := mongoNow(t, client)
		scan, err := q.Claim(ctx, "replica-1/worker-0")
		require.NoError(t, err)

		assert.Equal(t, older.ID, scan.ID)
		assert.Equal(t, store.ScanScanning, scan.State)
		assert.Equal(t, "replica-1/worker-0", scan.Worker)
		assert.Equal(t, 1, scan.Attempt)
		require.NotNil(t, scan.LeaseUntil)
		assert.WithinDuration(t, before.Add(60*time.Second), *scan.LeaseUntil, 2*time.Second)
		require.NotNil(t, scan.StartedAt)
	})
}

func TestFencedWrites(t *testing.T) {
	ctx := context.Background()

	t.Run("heartbeat extends the lease; a wrong attempt has lost it", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		_, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		scan, err := q.Claim(ctx, "w")
		require.NoError(t, err)
		setFields(t, client, scan.ID, bson.M{"$set": bson.M{"lease_until": time.Now().Add(-time.Hour)}})

		require.NoError(t, q.Heartbeat(ctx, scan))
		var doc store.Scan
		require.NoError(t, client.Database().Collection(store.CollectionScans).FindOne(ctx, bson.M{"_id": scan.ID}).Decode(&doc))
		assert.True(t, doc.LeaseUntil.After(mongoNow(t, client).Add(50*time.Second)))

		stale := scan
		stale.Attempt = 99
		assert.ErrorIs(t, q.Heartbeat(ctx, stale), queue.ErrLeaseLost)
	})

	t.Run("a stale worker's late completion is rejected", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		_, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		stale, err := q.Claim(ctx, "replica-1/worker-0")
		require.NoError(t, err)
		// The lease expired and the scan went back to the queue (the reaper's job).
		setFields(t, client, stale.ID, bson.M{"$set": bson.M{"state": "queued"}})
		current, err := q.Claim(ctx, "replica-2/worker-0")
		require.NoError(t, err)
		assert.Equal(t, 2, current.Attempt)

		stale.Result = &store.ScanResult{Summary: map[string]int{"critical": 99}}
		assert.ErrorIs(t, q.Complete(ctx, stale), queue.ErrLeaseLost)
		current.Result = &store.ScanResult{Summary: map[string]int{"critical": 1}}
		require.NoError(t, q.Complete(ctx, current))

		done := getScan(t, client, current.ID)
		assert.Equal(t, "done", done.State)
		assert.Equal(t, 1, done.Result.Summary["critical"], "the current worker's result")
		assert.ErrorIs(t, q.Fail(ctx, stale, "trivy_exit_error", "late"), queue.ErrLeaseLost)
	})

	t.Run("completion stores values literally and replaces the result", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		enqueued, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		finish(t, client, enqueued)
		setFields(t, client, enqueued.ID, bson.M{"$set": bson.M{"state": "queued"}})
		scan, err := q.Claim(ctx, "w")
		require.NoError(t, err)
		require.NotNil(t, scan.Result, "the previous result")
		scan.Result = &store.ScanResult{
			Digest:             "sha256:a",
			ImagePlatformTypes: []string{"$npm"},
			Report:             bson.M{"findings": bson.A{bson.M{"id": "CVE-1", "title": "$where injection in $gt"}}},
		}
		scan.DB = &store.ScanDB{ManifestDigest: "sha256:db", Freshness: "stale"}
		scan.ScanMS = 1234
		before := mongoNow(t, client)

		require.NoError(t, q.Complete(ctx, scan))

		done := getScan(t, client, scan.ID)
		assert.Equal(t, store.ScanDone, done.State)
		assert.Equal(t, []string{"$npm"}, done.Result.ImagePlatformTypes, "a value starting with $ is not read as a field path")
		finding := done.Result.Report["findings"].(bson.A)[0].(bson.D)
		assert.Contains(t, finding, bson.E{Key: "title", Value: "$where injection in $gt"})
		assert.Nil(t, done.Result.Summary, "the previous result is replaced, not merged")
		assert.Equal(t, &store.ScanDB{ManifestDigest: "sha256:db", Freshness: "stale", UpdatedAt: done.DB.UpdatedAt}, done.DB)
		require.NotNil(t, done.ConfirmedAt)
		assert.False(t, done.ConfirmedAt.Before(before.Add(-time.Second)), "confirmed_at on MongoDB's clock")
		assert.Nil(t, done.LeaseUntil)
		require.NotNil(t, done.FinishedAt)
		assert.Equal(t, int64(1234), done.ScanMS)
		assert.GreaterOrEqual(t, done.TotalMS, done.QueueWaitMS)
		assert.Equal(t, enqueued.ID, done.ID)
	})

	t.Run("a failed scan keeps the last good result; a retry queues the same document again", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		finish(t, client, first)
		_, _, err = q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		scan, err := q.Claim(ctx, "w")
		require.NoError(t, err)
		require.NoError(t, q.Fail(ctx, scan, "trivy_exit_error", "exit status 1"))

		failed := getScan(t, client, first.ID)
		assert.Equal(t, "failed", failed.State)
		assert.Equal(t, "trivy_exit_error", failed.FailureClass)
		assert.Equal(t, "exit status 1", failed.Error)
		require.NotNil(t, failed.Result, "the last good result stays")
		assert.Equal(t, 1, failed.Result.Summary["high"])

		retry, created, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		assert.True(t, created)
		assert.Equal(t, first.ID, retry.ID)
		assert.Equal(t, "queued", retry.State)
		assert.EqualValues(t, 1, countScans(t, client))
	})
}
