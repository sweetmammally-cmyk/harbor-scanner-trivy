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

// newScan is a scan as the API would enqueue it.
func newScan(requestID, digest string) store.Scan {
	scanCounter.Lock()
	scanNumber++
	id := fmt.Sprintf("scan-%d", scanNumber)
	scanCounter.Unlock()
	return store.Scan{
		ID:              id,
		RequestID:       requestID,
		RequestedAt:     time.Now(),
		CustomerIDs:     []string{"cust-1"},
		Image:           store.Image{Repository: "project", Name: "app", Tag: "v1", Digest: digest},
		Reference:       "harbor.local/project/app@" + digest,
		Options:         store.ScanOptions{Platforms: []string{"npm", "alpine"}, Severity: []string{"HIGH", "CRITICAL"}},
		ScannedPlatform: "linux/amd64",
		Trivy:           store.TrivyInfo{Version: "0.74.0"},
	}
}

func rawScan(t *testing.T, client *store.Client, id string) bson.M {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	var doc bson.M
	require.NoError(t, client.Database().Collection(store.CollectionScans).FindOne(ctx, bson.M{"_id": id}).Decode(&doc))
	return doc
}

func setFields(t *testing.T, client *store.Client, id string, update bson.M) {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	_, err := client.Database().Collection(store.CollectionScans).UpdateOne(ctx, bson.M{"_id": id}, update)
	require.NoError(t, err)
}

func TestEnqueue(t *testing.T) {
	ctx := context.Background()

	t.Run("a new scan is queued with its active key", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)

		scan, created, err := q.Enqueue(ctx, newScan("req-1", "sha256:a"))

		require.NoError(t, err)
		assert.True(t, created)
		doc := rawScan(t, client, scan.ID)
		assert.Equal(t, "queued", doc["state"])
		assert.Equal(t, queue.ActiveKey(scan), doc["active_key"])
		assert.EqualValues(t, 0, doc["attempt"])
		assert.NotContains(t, doc, "priority", "reserved, not set")
	})

	t.Run("the same request_id returns the first scan", func(t *testing.T) {
		q, _, _ := newQueue(t, nil)
		first, _, err := q.Enqueue(ctx, newScan("req-1", "sha256:a"))
		require.NoError(t, err)

		again, created, err := q.Enqueue(ctx, newScan("req-1", "sha256:other"))

		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, first.ID, again.ID)
	})

	t.Run("identical work shares one scan, whatever the order of the lists", func(t *testing.T) {
		q, _, _ := newQueue(t, nil)
		first, _, err := q.Enqueue(ctx, newScan("req-1", "sha256:a"))
		require.NoError(t, err)
		same := newScan("req-2", "sha256:a")
		same.Options = store.ScanOptions{Platforms: []string{"alpine", "npm"}, Severity: []string{"CRITICAL", "HIGH"}}

		again, created, err := q.Enqueue(ctx, same)

		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, first.ID, again.ID)
	})

	t.Run("different work is a new scan", func(t *testing.T) {
		q, _, _ := newQueue(t, nil)
		_, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		for name, change := range map[string]func(*store.Scan){
			"digest":           func(s *store.Scan) { s.Image.Digest = "sha256:b" },
			"platforms":        func(s *store.Scan) { s.Options.Platforms = []string{"npm"} },
			"severities":       func(s *store.Scan) { s.Options.Severity = []string{"LOW"} },
			"scanned platform": func(s *store.Scan) { s.ScannedPlatform = "linux/arm64" },
			"Trivy version":    func(s *store.Scan) { s.Trivy.Version = "0.75.0" },
		} {
			scan := newScan("", "sha256:a")
			change(&scan)
			_, created, err := q.Enqueue(ctx, scan)
			require.NoError(t, err, name)
			assert.True(t, created, name)
		}
	})

	t.Run("ten concurrent identical requests create one scan", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		var wg sync.WaitGroup
		ids := make([]string, 10)
		created := make([]bool, 10)
		errs := make([]error, 10)
		for i := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var scan store.Scan
				scan, created[i], errs[i] = q.Enqueue(ctx, newScan(fmt.Sprintf("req-%d", i), "sha256:same"))
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
		count, err := client.Database().Collection(store.CollectionScans).CountDocuments(ctx, bson.M{})
		require.NoError(t, err)
		assert.EqualValues(t, 1, count)
	})

	t.Run("ten concurrent requests with the same request_id create one scan", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := q.Enqueue(ctx, newScan("req-same", fmt.Sprintf("sha256:%d", i)))
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		count, err := client.Database().Collection(store.CollectionScans).CountDocuments(ctx, bson.M{})
		require.NoError(t, err)
		assert.EqualValues(t, 1, count)
	})

	t.Run("queue full: new work is refused, identical work still joins", func(t *testing.T) {
		q, _, _ := newQueue(t, func(cfg *config.Config) { cfg.QueueMaxLength = 2 })
		first, _, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		_, _, err = q.Enqueue(ctx, newScan("", "sha256:b"))
		require.NoError(t, err)

		_, _, err = q.Enqueue(ctx, newScan("", "sha256:c"))
		assert.ErrorIs(t, err, queue.ErrQueueFull)

		joined, created, err := q.Enqueue(ctx, newScan("", "sha256:a"))
		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, first.ID, joined.ID)
	})

	t.Run("a done scan stays idempotent; new identical work is a new scan", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		done, _, err := q.Enqueue(ctx, newScan("req-1", "sha256:a"))
		require.NoError(t, err)
		setFields(t, client, done.ID, bson.M{"$set": bson.M{"state": "done"}, "$unset": bson.M{"active_key": ""}})

		again, created, err := q.Enqueue(ctx, newScan("req-1", "sha256:a"))
		require.NoError(t, err)
		assert.False(t, created)
		assert.Equal(t, done.ID, again.ID)

		fresh, created, err := q.Enqueue(ctx, newScan("req-2", "sha256:a"))
		require.NoError(t, err)
		assert.True(t, created, "no active scan for this work any more")
		assert.NotEqual(t, done.ID, fresh.ID)
	})
}
