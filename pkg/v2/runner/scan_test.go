package runner

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	var logs bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(defaultLogger) })
	return &logs
}

func queuedScan() store.Scan {
	return store.Scan{
		ID:          "scan-1",
		CustomerIDs: []string{"cust-123"},
		Image:       store.Image{Repository: "project", Name: "app", Tag: "v1", Digest: "sha256:1111"},
		Options:     store.ScanOptions{Platforms: []string{"alpine", "npm"}, Severity: []string{"HIGH", "CRITICAL"}},
		State:       store.ScanScanning,
		QueuedAt:    time.Now(),
	}
}

// newScanRunner returns a test runner whose fake trivy answers with the fixture.
func newScanRunner(t *testing.T) (*Runner, *store.MemoryPlatforms) {
	r, _ := newTestRunner(t)
	platforms := store.NewMemoryPlatforms()
	r.platforms = platforms
	r.cfg.ScanMaxFindings = 100
	t.Setenv("TRIVY_FAKE_MODE", "fixture")
	absolute, err := filepath.Abs(fixture)
	require.NoError(t, err)
	t.Setenv("TRIVY_FAKE_FIXTURE", absolute)
	require.NoError(t, r.CheckTrivy(context.Background()))
	return r, platforms
}

func TestScan(t *testing.T) {
	r, platforms := newScanRunner(t)
	logs := captureLogs(t)

	scan, report, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

	require.NoError(t, err)
	require.NotNil(t, scan.DB)
	assert.Equal(t, store.ScanDB{UpdatedAt: time.Date(2026, 10, 15, 7, 10, 8, 0, time.UTC), ManifestDigest: "sha256:db-v1"},
		store.ScanDB{UpdatedAt: scan.DB.UpdatedAt.UTC(), ManifestDigest: scan.DB.ManifestDigest}, "freshness is set by the queue")
	summary := map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 1, "unknown": 0}
	assert.Equal(t, &store.ScanResult{
		Digest:             queuedScan().Image.Digest,
		Platforms:          []string{"alpine", "npm"},
		Severity:           []string{"HIGH", "CRITICAL"},
		ScannedPlatform:    "linux/amd64",
		TrivyVersion:       "0.74.0",
		ImagePlatformTypes: []string{"alpine", "node-pkg", "pip"},
		Summary:            summary,
		SummaryByPlatform:  map[string]map[string]int{"alpine": summary},
	}, scan.Result, "npm was asked for and is not in the image: no summary for it")
	assert.Greater(t, scan.ScanMS, int64(-1))
	findings := report["findings"].([]Finding)
	assert.Len(t, findings, 3)

	seen, err := platforms.List(context.Background())
	require.NoError(t, err)
	require.Len(t, seen, 3, "every platform of the image is recorded, requested or not")
	for _, platform := range seen {
		assert.Equal(t, "sha256:1111", platform.ExampleDigest)
	}
	assertNoOutputLeft(t, r)

	assert.Contains(t, logs.String(), `"msg":"triggering scan","scan_id":"scan-1","digest":"sha256:1111","customer_ids":["cust-123"],"platforms":["alpine","npm"],"severities":["HIGH","CRITICAL"],"trivy_version":"0.74.0","db_updated_at":"2026-10-15T07:10:08Z"`)
	assert.Contains(t, logs.String(), `"msg":"scan done"`)
	assert.Contains(t, logs.String(), `"findings_stored":3`)
	assert.Contains(t, logs.String(), `"platforms_not_found":["npm"]`)
	for _, finding := range findings {
		assert.NotContains(t, logs.String(), finding.ID, "findings are never logged")
	}
	assert.NotContains(t, logs.String(), robotPassword)
}

func TestScan_ReportIsStoredInlineOrInGridFS(t *testing.T) {
	r, _ := newScanRunner(t)
	scan, report, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)
	require.NoError(t, err)
	var saved store.Scan
	save := func(ctx context.Context, scan store.Scan) error {
		saved = scan
		return nil
	}

	inline := store.NewMemoryReports(store.ReportInlineLimit)
	require.NoError(t, store.SaveWithReport(context.Background(), inline, scan, report, save))
	assert.Nil(t, saved.Result.ReportGridFSID)
	assert.NotNil(t, saved.Result.Report)

	gridFS := store.NewMemoryReports(100)
	require.NoError(t, store.SaveWithReport(context.Background(), gridFS, scan, report, save))
	require.NotNil(t, saved.Result.ReportGridFSID)
	loaded, err := gridFS.Load(context.Background(), saved)
	require.NoError(t, err)
	assert.Len(t, loaded["findings"], 3)
	first := loaded["findings"].(bson.A)[0].(bson.D)
	assert.Equal(t, "id", first[0].Key, "stored with the finding field names")
}

func TestScan_Failures(t *testing.T) {
	t.Run("Trivy fails: classified, logged, nothing recorded", func(t *testing.T) {
		r, platforms := newScanRunner(t)
		t.Setenv("TRIVY_FAKE_MODE", "exit")
		logs := captureLogs(t)

		_, report, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		assertClass(t, err, FailureExit)
		assert.Nil(t, report)
		assert.Contains(t, logs.String(), `"level":"WARN","msg":"scan failed"`)
		assert.Contains(t, logs.String(), `"failure_class":"trivy_exit_error"`)
		assert.NotContains(t, logs.String(), robotPassword)
		seen, listErr := platforms.List(context.Background())
		require.NoError(t, listErr)
		assert.Empty(t, seen)
	})

	t.Run("invalid output: classified, output file removed", func(t *testing.T) {
		r, _ := newScanRunner(t)
		notJSON := filepath.Join(t.TempDir(), "out.txt")
		require.NoError(t, os.WriteFile(notJSON, []byte("Trivy crashed"), 0o644))
		t.Setenv("TRIVY_FAKE_FIXTURE", notJSON)

		_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		assertClass(t, err, FailureOutputInvalid)
		assertNoOutputLeft(t, r)
	})
}

func TestCheckTrivy(t *testing.T) {
	t.Run("version found: ready", func(t *testing.T) {
		r, _ := newTestRunner(t)

		require.NoError(t, r.CheckTrivy(context.Background()))

		assert.Equal(t, "0.74.0", r.Version())
		assert.True(t, r.Ready())
	})

	t.Run("version command fails: not ready", func(t *testing.T) {
		r, _ := newTestRunner(t)
		t.Setenv("TRIVY_FAKE_MODE", "badversion")

		assert.Error(t, r.CheckTrivy(context.Background()))
		assert.False(t, r.Ready())
	})

	t.Run("binary missing: not ready", func(t *testing.T) {
		r, _ := newTestRunner(t)
		r.trivy = filepath.Join(t.TempDir(), "no-trivy")

		err := r.CheckTrivy(context.Background())

		require.Error(t, err)
		assert.False(t, r.Ready())
	})
}
