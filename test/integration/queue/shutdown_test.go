//go:build integration

package queue

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/mongotest"
)

// startPool runs a pool and returns a function that stops it (SIGTERM) and
// waits until Run returns, returning how long that took.
func startPool(q *queue.Queue, scanner queue.Scanner) func() time.Duration {
	ctx, cancel := context.WithCancel(context.Background())
	pool := queue.NewPool(q, scanner, &fakeRefresher{}, store.NewMemoryReports(store.ReportInlineLimit), always, "replica-1")
	stopped := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(stopped)
	}()
	return func() time.Duration {
		start := time.Now()
		cancel()
		<-stopped
		return time.Since(start)
	}
}

func TestShutdown(t *testing.T) {
	ctx := context.Background()
	grace := func(cfg *config.Config) { cfg.ShutdownGrace = time.Second }

	t.Run("a scan that ends within the grace period is completed", func(t *testing.T) {
		q, client, _ := newQueue(t, grace)
		started := make(chan struct{})
		scanner := &fakeScanner{scan: func(ctx context.Context, scan store.Scan) (store.Scan, bson.M, error) {
			close(started)
			time.Sleep(300 * time.Millisecond)
			scan.Result = &store.ScanResult{Digest: scan.Image.Digest}
			scan.DB = &store.ScanDB{}
			return scan, bson.M{"findings": bson.A{}}, nil
		}}
		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		stop := startPool(q, scanner)
		<-started

		took := stop()

		assert.Less(t, took, time.Second, "Run returns when the scan is done, not at the end of the grace")
		assert.Equal(t, "done", stateOf(t, client, scan.ID))
	})

	t.Run("a scan still running at the end of the grace is killed and released", func(t *testing.T) {
		q, client, cfg := newQueue(t, grace)
		started := make(chan struct{})
		scanner := &fakeScanner{scan: func(ctx context.Context, scan store.Scan) (store.Scan, bson.M, error) {
			close(started)
			<-ctx.Done() // like Trivy, killed when the context ends
			return scan, nil, ctx.Err()
		}}
		request := newScan("", "sha256:a")
		request.LastRequestID = "req-1"
		scan, _, err := q.Enqueue(ctx, request)
		require.NoError(t, err)
		stop := startPool(q, scanner)
		<-started

		took := stop()

		assert.GreaterOrEqual(t, took, time.Second)
		assert.Less(t, took, 3*time.Second)
		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "queued", doc["state"], "back in the queue at once, no lease expiry needed")
		assert.EqualValues(t, 0, doc["attempt"], "the attempt is not counted")
		assert.Equal(t, "req-1", doc["last_request_id"])
		for _, field := range []string{"worker", "lease_until", "started_at", "failure_class", "finished_at"} {
			assert.NotContains(t, doc, field)
		}

		// Another replica takes it up.
		other := startPool(queue.New(mongotest.Client(t, cfg), cfg), doneScanner())
		defer other()
		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "done" }, 10*time.Second, 20*time.Millisecond)
		assert.EqualValues(t, 1, rawScan(t, client, scan.ID)["attempt"])
	})

	t.Run("no scan is claimed after shutdown starts", func(t *testing.T) {
		q, client, _ := newQueue(t, grace)
		scanner := doneScanner()
		stop := startPool(q, scanner)
		stop()

		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		time.Sleep(300 * time.Millisecond)

		assert.Equal(t, "queued", stateOf(t, client, scan.ID))
		assert.EqualValues(t, 0, scanner.calls.Load())
	})
}
