//go:build integration

package queue

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/mongotest"
)

func shortLease(cfg *config.Config) {
	cfg.QueueLease = 200 * time.Millisecond
}

func TestReap(t *testing.T) {
	ctx := context.Background()

	t.Run("a scan whose lease has not expired is left alone", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		_, err = q.Claim(ctx, "w")
		require.NoError(t, err)

		requeued, failed, err := q.Reap(ctx)

		require.NoError(t, err)
		assert.Zero(t, requeued)
		assert.Zero(t, failed)
		assert.Equal(t, "scanning", stateOf(t, client, scan.ID))
	})

	t.Run("a killed worker's scan is requeued and finished by another replica", func(t *testing.T) {
		dead, client, cfg := newQueue(t, shortLease)
		scan, _, err := dead.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		_, err = dead.Claim(ctx, "replica-dead/worker-0") // and then it dies: no heartbeat
		require.NoError(t, err)
		time.Sleep(300 * time.Millisecond)

		other := queue.New(mongotest.Client(t, cfg), cfg)
		requeued, failed, err := other.Reap(ctx)
		require.NoError(t, err)
		assert.EqualValues(t, 1, requeued)
		assert.Zero(t, failed)
		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "queued", doc["state"])
		assert.NotContains(t, doc, "worker")
		assert.NotContains(t, doc, "lease_until")
		assert.Equal(t, queue.ActiveKey(scan), doc["active_key"], "still the active scan for its work")

		runPool(t, other, doneScanner(), &fakeRefresher{}, always)

		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "done" }, 10*time.Second, 20*time.Millisecond)
		doc = rawScan(t, client, scan.ID)
		assert.EqualValues(t, 2, doc["attempt"])
		assert.Equal(t, "replica-1/worker-0", doc["worker"])
	})

	t.Run("a poison job fails with worker_lost after the maximum attempts", func(t *testing.T) {
		q, client, _ := newQueue(t, func(cfg *config.Config) {
			shortLease(cfg)
			cfg.QueueMaxAttempts = 2
		})
		scan, _, err := q.Enqueue(ctx, newScan("req-poison", "sha256:a"))
		require.NoError(t, err)

		for attempt := 1; attempt <= 2; attempt++ {
			claimed, err := q.Claim(ctx, "w")
			require.NoError(t, err, "attempt %d", attempt)
			assert.Equal(t, attempt, claimed.Attempt)
			time.Sleep(300 * time.Millisecond) // the worker dies each time
			_, _, err = q.Reap(ctx)
			require.NoError(t, err)
		}

		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "failed", doc["state"])
		assert.Equal(t, queue.FailureWorkerLost, doc["failure_class"])
		assert.Equal(t, "req-poison", doc["prior_request_id"])
		assert.NotContains(t, doc, "active_key")
		assert.NotContains(t, doc, "request_id")
		_, err = q.Claim(ctx, "w")
		assert.ErrorIs(t, err, queue.ErrNoJob, "a failed scan is not claimed again")

		retry, created, err := q.Enqueue(ctx, newScan("req-poison", "sha256:a"))
		require.NoError(t, err)
		assert.True(t, created)
		assert.NotEqual(t, scan.ID, retry.ID)
	})

	t.Run("the reaper runs by itself on its interval once MongoDB is ready", func(t *testing.T) {
		q, client, _ := newQueue(t, shortLease)
		monitorCtx, stopMonitor := context.WithCancel(ctx)
		defer stopMonitor()
		go client.Monitor(monitorCtx, 50*time.Millisecond)
		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		_, err = q.Claim(ctx, "w")
		require.NoError(t, err)

		reaperCtx, stopReaper := context.WithCancel(ctx)
		defer stopReaper()
		go q.RunReaper(reaperCtx, 100*time.Millisecond)

		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "queued" }, 5*time.Second, 20*time.Millisecond)
	})
}
