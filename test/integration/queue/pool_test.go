//go:build integration

package queue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// fakeScanner stands in for the scan runner.
type fakeScanner struct {
	scan  func(ctx context.Context, scan store.Scan) (store.Scan, bson.M, error)
	calls atomic.Int32
}

func (f *fakeScanner) Scan(ctx context.Context, worker string, scan store.Scan, reference string) (store.Scan, bson.M, error) {
	f.calls.Add(1)
	return f.scan(ctx, scan)
}

// doneScanner finishes every scan at once with one finding.
func doneScanner() *fakeScanner {
	return &fakeScanner{scan: func(ctx context.Context, scan store.Scan) (store.Scan, bson.M, error) {
		scan.Summary = map[string]int{"high": 1}
		scan.Trivy.DBManifestDigest = "sha256:db"
		return scan, bson.M{"findings": bson.A{bson.M{"id": "CVE-1"}}}, nil
	}}
}

// fakeRefresher records the max ages it was asked for.
type fakeRefresher struct {
	mu      sync.Mutex
	maxAges []time.Duration
}

func (f *fakeRefresher) RefreshForScan(ctx context.Context, maxAge time.Duration) (dbmgr.DBState, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxAges = append(f.maxAges, maxAge)
	return dbmgr.DBState{}, dbmgr.FreshnessOK, nil
}

// runPool runs a pool until the end of the test.
func runPool(t *testing.T, q *queue.Queue, scanner queue.Scanner, refresher queue.Refresher, ready func() bool) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := queue.NewPool(q, scanner, refresher, store.NewMemoryReports(store.ReportInlineLimit), ready, "replica-1")
	stopped := make(chan struct{})
	go func() {
		pool.Run(ctx)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
}

func stateOf(t *testing.T, client *store.Client, id string) string {
	return rawScan(t, client, id)["state"].(string)
}

func always() bool { return true }

func TestPool(t *testing.T) {
	ctx := context.Background()

	t.Run("a queued scan is run and completed, after the on-demand refresh", func(t *testing.T) {
		q, client, _ := newQueue(t, func(cfg *config.Config) { cfg.QueueWorkers = 2; cfg.DBMaxAgeDefault = 6 * time.Hour })
		refresher := &fakeRefresher{}
		withAge := newScan("", "sha256:a")
		withAge.Options.MaxDBAge = time.Hour
		first, _, err := q.Enqueue(ctx, withAge)
		require.NoError(t, err)
		second, _, err := q.Enqueue(ctx, newScan("", "sha256:b"))
		require.NoError(t, err)

		runPool(t, q, doneScanner(), refresher, always)

		require.Eventually(t, func() bool {
			return stateOf(t, client, first.ID) == "done" && stateOf(t, client, second.ID) == "done"
		}, 10*time.Second, 20*time.Millisecond)
		doc := rawScan(t, client, first.ID)
		assert.Equal(t, "sha256:db", doc["trivy"].(bson.D)[2].Value)
		refresher.mu.Lock()
		assert.ElementsMatch(t, []time.Duration{time.Hour, 6 * time.Hour}, refresher.maxAges,
			"the request's max_db_age, or the default")
		refresher.mu.Unlock()
	})

	t.Run("a scan error marks the scan failed with its class", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		scanner := &fakeScanner{scan: func(ctx context.Context, scan store.Scan) (store.Scan, bson.M, error) {
			return scan, nil, &runner.ScanError{Class: runner.FailureJavaDBMissing, Detail: "no Java DB"}
		}}
		scan, _, err := q.Enqueue(ctx, newScan("req-1", "sha256:a"))
		require.NoError(t, err)

		runPool(t, q, scanner, &fakeRefresher{}, always)

		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "failed" }, 10*time.Second, 20*time.Millisecond)
		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "java_db_missing", doc["failure_class"])
		assert.Equal(t, "req-1", doc["prior_request_id"])
	})

	t.Run("workers do not claim while not ready", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		var ready atomic.Bool
		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)

		runPool(t, q, doneScanner(), &fakeRefresher{}, ready.Load)
		time.Sleep(300 * time.Millisecond)
		assert.Equal(t, "queued", stateOf(t, client, scan.ID))

		ready.Store(true)
		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "done" }, 10*time.Second, 20*time.Millisecond)
	})

	t.Run("an enqueue wakes an idle worker at once", func(t *testing.T) {
		q, client, _ := newQueue(t, func(cfg *config.Config) { cfg.QueuePollInterval = time.Hour })
		runPool(t, q, doneScanner(), &fakeRefresher{}, always)
		time.Sleep(100 * time.Millisecond) // the worker found nothing and waits for an hour

		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)

		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "done" }, 2*time.Second, 20*time.Millisecond)
	})

	t.Run("a lost lease cancels the scan and discards its result", func(t *testing.T) {
		q, client, _ := newQueue(t, func(cfg *config.Config) { cfg.QueueLease = 300 * time.Millisecond })
		cancelled := make(chan struct{})
		scanner := &fakeScanner{scan: func(ctx context.Context, scan store.Scan) (store.Scan, bson.M, error) {
			<-ctx.Done() // like Trivy, killed when the context ends
			close(cancelled)
			scan.Summary = map[string]int{"critical": 99}
			return scan, bson.M{}, errors.New("killed")
		}}
		scan, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		runPool(t, q, scanner, &fakeRefresher{}, always)
		require.Eventually(t, func() bool { return stateOf(t, client, scan.ID) == "scanning" }, 5*time.Second, 10*time.Millisecond)

		// Another replica took the scan over (its attempt changed).
		setFields(t, client, scan.ID, bson.M{"$set": bson.M{"attempt": 7, "worker": "replica-2/worker-0"}})

		select {
		case <-cancelled:
		case <-time.After(5 * time.Second):
			t.Fatal("the scan was not cancelled after its lease was lost")
		}
		time.Sleep(200 * time.Millisecond)
		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "scanning", doc["state"], "nothing written by the worker that lost the lease")
		assert.NotContains(t, doc, "failure_class")
		assert.EqualValues(t, 7, doc["attempt"])
	})
}
