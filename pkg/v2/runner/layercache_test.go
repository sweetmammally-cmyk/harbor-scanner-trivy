package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// TestTrimLayerCache: after a scan, a worker whose layer cache is larger than
// SCANNER_V2_WORKER_CACHE_MAX clears it; the DB links and other workers stay.
func TestTrimLayerCache(t *testing.T) {
	setup := func(t *testing.T, size int64) (*Runner, string) {
		r, _ := newScanRunner(t)
		r.cfg.WorkerCacheMax = 5 << 30
		r.dirSize = func(path string) (int64, error) { return size, nil }
		layerCache := filepath.Join(r.workDir, "worker-1", "fanal")
		require.NoError(t, os.MkdirAll(layerCache, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(layerCache, "fanal.db"), []byte("layers"), 0o600))
		other := filepath.Join(r.workDir, "worker-2", "fanal", "fanal.db")
		require.NoError(t, os.MkdirAll(filepath.Dir(other), 0o700))
		require.NoError(t, os.WriteFile(other, []byte("layers"), 0o600))
		return r, layerCache
	}

	t.Run("over the limit: cleared after the scan, DBs and other workers kept", func(t *testing.T) {
		r, layerCache := setup(t, 6<<30)
		logs := captureLogs(t)

		_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		require.NoError(t, err)
		assert.NoDirExists(t, layerCache)
		assert.FileExists(t, filepath.Join(r.workDir, "worker-1", "db", "trivy.db"), "the DB link stays")
		assert.FileExists(t, filepath.Join(r.workDir, "worker-2", "fanal", "fanal.db"), "only its own cache")
		assert.Contains(t, logs.String(), `"msg":"worker layer cache cleared"`)
	})

	t.Run("at the limit: kept", func(t *testing.T) {
		r, layerCache := setup(t, 5<<30)

		_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		require.NoError(t, err)
		assert.DirExists(t, layerCache)
	})

	t.Run("also after a failed scan", func(t *testing.T) {
		r, layerCache := setup(t, 6<<30)
		t.Setenv("TRIVY_FAKE_MODE", "exit")

		_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		require.Error(t, err)
		assert.NoDirExists(t, layerCache)
	})

	t.Run("the memory backend has nothing to trim", func(t *testing.T) {
		r, layerCache := setup(t, 6<<30)
		r.cfg.WorkerCacheBackend = config.CacheBackendMemory
		measured := false
		r.dirSize = func(path string) (int64, error) { measured = true; return 6 << 30, nil }

		_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		require.NoError(t, err)
		assert.False(t, measured)
		assert.DirExists(t, layerCache)
	})
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "x"), make([]byte, 300), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "y"), make([]byte, 200), 0o600))

	size, err := dirSize(dir)
	require.NoError(t, err)
	assert.EqualValues(t, 500, size)

	size, err = dirSize(filepath.Join(dir, "missing"))
	require.NoError(t, err)
	assert.Zero(t, size)
}
