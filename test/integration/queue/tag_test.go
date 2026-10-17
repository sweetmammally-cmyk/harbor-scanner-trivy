//go:build integration

package queue

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// countingScanner gives the n-th scan a summary of n high findings and a report
// too large to stay inline. failFrom > 0 makes scans from that one on fail.
type countingScanner struct {
	failFrom int

	mu      sync.Mutex
	scans   int
	options []store.ScanOptions
}

func (c *countingScanner) Scan(ctx context.Context, worker string, scan store.Scan, reference string) (store.Scan, bson.M, error) {
	c.mu.Lock()
	c.scans++
	n := c.scans
	c.options = append(c.options, scan.Options)
	c.mu.Unlock()
	if c.failFrom > 0 && n >= c.failFrom {
		return scan, nil, &runner.ScanError{Class: runner.FailureExit, Detail: "exit status 1"}
	}
	scan.Result = &store.ScanResult{Digest: scan.Image.Digest, Platforms: scan.Options.Platforms, Severity: scan.Options.Severity,
		Summary: map[string]int{"high": n}}
	scan.DB = &store.ScanDB{ManifestDigest: "sha256:db"}
	return scan, bson.M{"findings": strings.Repeat(fmt.Sprintf("CVE-%d ", n), 50)}, nil
}

// reportFiles returns the ids of the GridFS files of a scan document.
func reportFiles(t *testing.T, client *store.Client, scanID string) []bson.ObjectID {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	cursor, err := client.Database().Collection(store.ReportBucket+".files").Find(ctx, bson.M{"metadata.scan_id": scanID})
	require.NoError(t, err)
	var files []struct {
		ID bson.ObjectID `bson:"_id"`
	}
	require.NoError(t, cursor.All(ctx, &files))
	var ids []bson.ObjectID
	for _, file := range files {
		ids = append(ids, file.ID)
	}
	return ids
}

// highOf returns the stored result's high count, or -1 without a result.
func highOf(t *testing.T, client *store.Client, id string) int {
	scan := getScan(t, client, id)
	if scan.Result == nil {
		return -1
	}
	return scan.Result.Summary["high"]
}

func TestOneDocumentPerTag(t *testing.T) {
	ctx := context.Background()
	eventually := func(t *testing.T, condition func() bool) {
		require.Eventually(t, condition, 10*time.Second, 20*time.Millisecond)
	}

	t.Run("the same tag scanned twice: one document, the result replaced, the old GridFS file deleted", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		reports := store.NewMongoReports(client, 100)
		runPoolWithReports(t, q, &countingScanner{}, &fakeRefresher{}, always, reports)

		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		eventually(t, func() bool { return stateOf(t, client, first.ID) == "done" })
		firstFiles := reportFiles(t, client, first.ID)
		require.Len(t, firstFiles, 1)

		_, created, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		assert.True(t, created)
		eventually(t, func() bool { return stateOf(t, client, first.ID) == "done" && highOf(t, client, first.ID) == 2 })

		assert.EqualValues(t, 1, countScans(t, client))
		files := reportFiles(t, client, first.ID)
		require.Len(t, files, 1, "the previous result's file is deleted")
		assert.NotEqual(t, firstFiles[0], files[0])
		done := getScan(t, client, first.ID)
		assert.Equal(t, files[0], *done.Result.ReportGridFSID)
		report, err := reports.Load(ctx, done)
		require.NoError(t, err)
		assert.Contains(t, report["findings"], "CVE-2 ")
	})

	t.Run("a failed rescan keeps the last good result and its report", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		reports := store.NewMongoReports(client, 100)
		runPoolWithReports(t, q, &countingScanner{failFrom: 2}, &fakeRefresher{}, always, reports)

		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		eventually(t, func() bool { return stateOf(t, client, first.ID) == "done" })
		goodFiles := reportFiles(t, client, first.ID)

		_, _, err = q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		eventually(t, func() bool { return stateOf(t, client, first.ID) == "failed" })

		failed := getScan(t, client, first.ID)
		assert.Equal(t, runner.FailureExit, failed.FailureClass)
		require.NotNil(t, failed.Result)
		assert.Equal(t, 1, failed.Result.Summary["high"], "the last good result")
		assert.Equal(t, goodFiles, reportFiles(t, client, first.ID), "and its file")
		report, err := reports.Load(ctx, failed)
		require.NoError(t, err)
		assert.Contains(t, report["findings"], "CVE-1 ")
	})

	t.Run("a rescan of the same digest scans the union of the scopes", func(t *testing.T) {
		q, client, _ := newQueue(t, nil)
		scanner := &countingScanner{}
		runPool(t, q, scanner, &fakeRefresher{}, always)

		first, _, err := q.Enqueue(ctx, newScan("v1", "sha256:a"))
		require.NoError(t, err)
		eventually(t, func() bool { return stateOf(t, client, first.ID) == "done" })

		wider := newScan("v1", "sha256:a")
		wider.Options = store.ScanOptions{Platforms: []string{"pip"}, Severity: []string{"MEDIUM"}}
		_, _, err = q.Enqueue(ctx, wider)
		require.NoError(t, err)
		eventually(t, func() bool { return highOf(t, client, first.ID) == 2 })

		union := store.ScanOptions{Platforms: []string{"alpine", "npm", "pip"}, Severity: []string{"CRITICAL", "HIGH", "MEDIUM"}}
		scanner.mu.Lock()
		assert.Equal(t, union, scanner.options[1], "the scanner got the union")
		scanner.mu.Unlock()
		done := getScan(t, client, first.ID)
		assert.Equal(t, union.Platforms, done.Result.Platforms)
		assert.Equal(t, union.Severity, done.Result.Severity)
	})
}
