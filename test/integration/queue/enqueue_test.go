//go:build integration

package queue

import (
	"context"
	"fmt"
	"os"
	"sync"
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

// mongoAddr is the MongoDB shared by the package's tests (one database per test).
var mongoAddr string

func TestMain(m *testing.M) {
	addr, stop, err := mongotest.StartContainer()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	mongoAddr = addr
	code := m.Run()
	stop()
	os.Exit(code)
}

// newQueue returns a queue on a fresh database, with the given settings.
func newQueue(t *testing.T, change func(cfg *config.Config)) (*queue.Queue, *store.Client, config.Config) {
	cfg := mongotest.Config(mongoAddr)
	cfg.QueueMaxLength = 100
	cfg.QueueWorkers = 1
	cfg.QueueLease = 60 * time.Second
	cfg.QueueMaxAttempts = 3
	cfg.QueuePollInterval = 50 * time.Millisecond
	cfg.ShutdownGrace = 5 * time.Second
	if change != nil {
		change(&cfg)
	}
	client := mongotest.Client(t, cfg)
	return queue.New(client, cfg), client, cfg
}

var scanCounter sync.Mutex
var scanNumber int

// newScan is a scan as the API would enqueue it, for an image tag; an empty tag
// is a new tag each time (a new document).
func newScan(tag, digest string) store.Scan {
	if tag == "" {
		scanCounter.Lock()
		scanNumber++
		tag = fmt.Sprintf("t%d", scanNumber)
		scanCounter.Unlock()
	}
	return store.Scan{
		RequestedAt: time.Now(),
		CustomerIDs: []string{"cust-1"},
		Image:       store.Image{Repository: "project", Name: "app", Tag: tag, Digest: digest},
		Reference:   "harbor.local/project/app@" + digest,
		Options:     store.ScanOptions{Platforms: []string{"npm", "alpine"}, Severity: []string{"HIGH", "CRITICAL"}},
	}
}

func rawScan(t *testing.T, client *store.Client, id string) bson.M {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	var doc bson.M
	require.NoError(t, client.Database().Collection(store.CollectionScans).FindOne(ctx, bson.M{"_id": id}).Decode(&doc))
	return doc
}

func getScan(t *testing.T, client *store.Client, id string) store.Scan {
	scan, err := store.NewMongoScans(client).Get(context.Background(), id)
	require.NoError(t, err)
	return scan
}

func setFields(t *testing.T, client *store.Client, id string, update bson.M) {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	_, err := client.Database().Collection(store.CollectionScans).UpdateOne(ctx, bson.M{"_id": id}, update)
	require.NoError(t, err)
}

func countScans(t *testing.T, client *store.Client) int64 {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	count, err := client.Database().Collection(store.CollectionScans).CountDocuments(ctx, bson.M{})
	require.NoError(t, err)
	return count
}

// finish marks a tag's scan done with a result for its digest and options, as
// a completed scan would.
func finish(t *testing.T, client *store.Client, scan store.Scan) {
	result := store.ScanResult{Digest: scan.Image.Digest, Platforms: scan.Options.Platforms, Severity: scan.Options.Severity,
		Summary: map[string]int{"high": 1}}
	setFields(t, client, scan.ID, bson.M{"$set": bson.M{"state": "done", "result": result, "db": store.ScanDB{Freshness: "ok"}}})
}

func TestEnqueue(t *testing.T) {
	ctx := context.Background()

	t.Run("the first scan of a tag creates its document", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		request := newScan("v1", "sha256:a")
		request.LastRequestID = "req-1"

		scan, created, err := q.Enqueue(ctx, request)

		require.NoError(t, err)
		assert.True(t, created)
		assert.Equal(t, store.ScanID(request.Image), scan.ID, "the scan_id is the tag's id")
		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "queued", doc["state"])
		assert.EqualValues(t, 0, doc["attempt"])
		assert.Equal(t, "req-1", doc["last_request_id"])
		for _, absent := range []string{"priority", "result", "db", "confirmed_at", "request_id", "active_key"} {
			assert.NotContains(t, doc, absent)
		}
	})

	t.Run("while the tag is queued: a covered request joins, any other gets scan_in_progress", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)

		covered := newScan("v1", "sha256:a")
		covered.Options = store.ScanOptions{Platforms: []string{"alpine"}, Severity: []string{"CRITICAL"}}
		joined, created, err := q.Enqueue(ctx, covered)
		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, first.ID, joined.ID)
		assert.Equal(t, "queued", joined.State)

		for name, change := range map[string]func(*store.Scan){
			"another digest":   func(s *store.Scan) { s.Image.Digest = "sha256:b" },
			"another platform": func(s *store.Scan) { s.Options.Platforms = []string{"npm", "pip"} },
			"a lower severity": func(s *store.Scan) { s.Options.Severity = []string{"LOW"} },
		} {
			request := newScan("v1", "sha256:a")
			change(&request)
			_, _, err := q.Enqueue(ctx, request)
			assert.ErrorIs(t, err, queue.ErrScanInProgress, name)
		}
		assert.EqualValues(t, 1, countScans(t, client))
	})

	t.Run("while the tag is scanning: an uncovered request gets scan_in_progress", func(t *testing.T) {
		q, _, _ := newQueue(t, nil)
		_, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		claimed, err := q.Claim(ctx, "replica-1/worker-0")
		require.NoError(t, err)

		joined, created, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, "scanning", joined.State)
		assert.Equal(t, claimed.ID, joined.ID)

		wider := newScan("v1", "sha256:a")
		wider.Options.Platforms = []string{"jar"}
		_, _, err = q.Enqueue(ctx, wider)
		assert.ErrorIs(t, err, queue.ErrScanInProgress)
	})

	t.Run("ten concurrent requests for one tag on several replicas create one document and one scan", func(t *testing.T) {
		q, client, cfg := newQueue(t, nil)
		replicas := []*queue.Queue{q, queue.New(mongotest.Client(t, cfg), cfg), queue.New(mongotest.Client(t, cfg), cfg)}
		var wg sync.WaitGroup
		ids := make([]string, 10)
		created := make([]bool, 10)
		errs := make([]error, 10)
		for i := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				request := newScan("v1", "sha256:same")
				request.LastRequestID = fmt.Sprintf("req-%d", i)
				var scan store.Scan
				scan, created[i], errs[i] = replicas[i%len(replicas)].Enqueue(ctx, request)
				ids[i] = scan.ID
			}()
		}
		wg.Wait()

		createdCount := 0
		for i := range ids {
			require.NoError(t, errs[i])
			assert.Equal(t, ids[0], ids[i], "everyone gets the same scan_id")
			if created[i] {
				createdCount++
			}
		}
		assert.Equal(t, 1, createdCount)
		assert.EqualValues(t, 1, countScans(t, client))
		_, err := q.Claim(ctx, "w")
		require.NoError(t, err)
		_, err = q.Claim(ctx, "w")
		assert.ErrorIs(t, err, queue.ErrNoJob, "one scan")
	})

	t.Run("queue full: a new scan is refused, a covered request still joins", func(t *testing.T) {
		q, _, _ := newQueue(t, func(cfg *config.Config) { cfg.QueueMaxLength = 2 })
		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		_, _, err = q.Enqueue(ctx, newScan("v2", "sha256:b"))
		require.NoError(t, err)

		_, _, err = q.Enqueue(ctx, newScan("v3", "sha256:c"))
		assert.ErrorIs(t, err, queue.ErrQueueFull)

		joined, created, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, first.ID, joined.ID)
	})

	t.Run("a rescan of the same digest widens the scope to the union and keeps the result until it succeeds", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		finish(t, client, first)
		setFields(t, client, first.ID, bson.M{"$set": bson.M{"state": "failed", "error": "old", "failure_class": "trivy_timeout"}})

		request := newScan("v1", "sha256:a")
		request.Options = store.ScanOptions{Platforms: []string{"pip"}, Severity: []string{"MEDIUM", "HIGH"}, MaxDBAge: time.Hour}
		request.CustomerIDs = []string{"cust-2"}
		request.LastRequestID = "req-2"
		requeued, created, err := q.Enqueue(ctx, request)

		require.NoError(t, err)
		assert.True(t, created, "a new scan of the tag")
		assert.Equal(t, first.ID, requeued.ID, "the same document")
		assert.EqualValues(t, 1, countScans(t, client))
		stored := getScan(t, client, first.ID)
		assert.Equal(t, store.ScanQueued, stored.State)
		assert.Equal(t, store.ScanOptions{Platforms: []string{"alpine", "npm", "pip"}, Severity: []string{"CRITICAL", "HIGH", "MEDIUM"},
			MaxDBAge: time.Hour}, stored.Options)
		assert.Equal(t, stored.Options, requeued.Options)
		require.NotNil(t, stored.Result, "the last result stays until the new scan succeeds")
		assert.Equal(t, []string{"npm", "alpine"}, stored.Result.Platforms)
		assert.Equal(t, []string{"cust-2"}, stored.CustomerIDs)
		assert.Equal(t, "req-2", stored.LastRequestID)
		assert.Empty(t, stored.Error)
		assert.Empty(t, stored.FailureClass)
		assert.Zero(t, stored.Attempt)
	})

	t.Run("a rescan after the tag moved to another digest uses the request's scope", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		finish(t, client, first)

		moved := newScan("v1", "sha256:b")
		moved.Options = store.ScanOptions{Platforms: []string{"pip"}, Severity: []string{"HIGH"}}
		_, created, err := q.Enqueue(ctx, moved)

		require.NoError(t, err)
		assert.True(t, created)
		stored := getScan(t, client, first.ID)
		assert.Equal(t, []string{"pip"}, stored.Options.Platforms)
		assert.Equal(t, []string{"HIGH"}, stored.Options.Severity)
		assert.Equal(t, "sha256:b", stored.Image.Digest)
		assert.Equal(t, "harbor.local/project/app@sha256:b", stored.Reference)
		assert.Equal(t, "sha256:a", stored.Result.Digest, "the last result, for the old digest, stays")
	})
}
