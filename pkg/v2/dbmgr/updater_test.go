package dbmgr

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// countRequests counts the fake registry's manifest and blob requests.
func countRequests(f *fakeOCIRegistry) (manifests, blobs *atomic.Int32) {
	manifests, blobs = &atomic.Int32{}, &atomic.Int32{}
	next := f.registry.Config.Handler
	f.registry.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			manifests.Add(1)
		}
		if strings.Contains(r.URL.Path, "/blobs/") {
			blobs.Add(1)
		}
		next.ServeHTTP(w, r)
	})
	return manifests, blobs
}

// startCountingRefuser accepts TCP connections and closes them at once, so the
// pre-check fails (tls_reset). It returns a source and the number of connections.
func startCountingRefuser(t *testing.T) (config.DBSource, *atomic.Int32) {
	var accepted atomic.Int32
	addr := listen(t, func(conn net.Conn) {
		accepted.Add(1)
	})
	return directSource(t, addr), &accepted
}

// runUpdater starts Run in the background and stops it at the end of the test.
func runUpdater(t *testing.T, cfg config.Config, cacheDir string) *Updater {
	ctx, cancel := context.WithCancel(context.Background())
	updater := NewUpdater(ctx, cfg, cacheDir, NewMemoryStateStore())
	stopped := make(chan struct{})
	go func() {
		updater.Run()
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop after the context ended")
		}
	})
	return updater
}

func TestUpdater_Run(t *testing.T) {
	t.Run("updates at startup and then every check interval", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
		manifests, blobs := countRequests(f)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		cfg.DBCheckInterval = 100 * time.Millisecond
		cfg.DBRetryInterval = time.Hour

		runUpdater(t, cfg, cacheDir)

		require.Eventually(t, func() bool { return InstalledDigest(cacheDir, "db") == f.manifestDigest },
			5*time.Second, 10*time.Millisecond, "first run at startup")
		// Each run asks for the manifest twice (pre-check and upstream check).
		require.Eventually(t, func() bool { return manifests.Load() >= 6 }, 5*time.Second, 10*time.Millisecond,
			"later runs on the check interval")
		assert.Equal(t, int32(1), blobs.Load(), "later runs find the DB up to date")
	})

	t.Run("uses the retry interval while degraded", func(t *testing.T) {
		source, connections := startCountingRefuser(t)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{source}
		cfg.DBCheckInterval = time.Hour
		cfg.DBRetryInterval = 50 * time.Millisecond

		runUpdater(t, cfg, t.TempDir())

		require.Eventually(t, func() bool { return connections.Load() >= 3 }, 5*time.Second, 10*time.Millisecond)
	})

	t.Run("goes back to the check interval after a success", func(t *testing.T) {
		cacheDir := t.TempDir()
		layer := dbLayer(t, "db", time.Now())
		f := startFakeOCIRegistry(t, layer)
		var blobCalls atomic.Int32
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			if blobCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway) // the first run fails: degraded, newer available
				return
			}
			_, _ = w.Write(layer)
		})
		manifests, _ := countRequests(f)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		cfg.DBCheckInterval = time.Hour
		cfg.DBRetryInterval = 50 * time.Millisecond

		runUpdater(t, cfg, cacheDir)

		require.Eventually(t, func() bool { return InstalledDigest(cacheDir, "db") == f.manifestDigest },
			5*time.Second, 10*time.Millisecond, "the retry installs the DB")
		afterInstall := manifests.Load()
		time.Sleep(300 * time.Millisecond)
		assert.Equal(t, afterInstall, manifests.Load(), "no more runs: the check interval (1h) applies again")
		assert.Equal(t, int32(2), blobCalls.Load())
	})

	t.Run("installs the seed before the first update", func(t *testing.T) {
		cacheDir := t.TempDir()
		seedDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(seedDir, "trivy.db"), []byte("seed db"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(seedDir, "metadata.json"), []byte("{}"), 0o644))
		javaSeedDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(javaSeedDir, "trivy-java.db"), []byte("java seed"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(javaSeedDir, "metadata.json"), []byte("{}"), 0o644))
		source, _ := startCountingRefuser(t)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{source}
		cfg.DBSeedDir = seedDir
		cfg.JavaDBSeedDir = javaSeedDir
		cfg.DBCheckInterval = time.Hour
		cfg.DBRetryInterval = time.Hour

		runUpdater(t, cfg, cacheDir)

		require.Eventually(t, func() bool { return dbPresent(cacheDir, "db", "trivy.db") }, 5*time.Second, 10*time.Millisecond)
		assert.Equal(t, "seed db", readDB(t, cacheDir), "all sources fail, the seed stays")
		assert.False(t, dbPresent(cacheDir, "java-db", "trivy-java.db"), "no Java sources: no Java DB, not even the seed")
	})
}

func TestUpdater_UpdateNow(t *testing.T) {
	t.Run("concurrent callers share one run", func(t *testing.T) {
		cacheDir := t.TempDir()
		layer := dbLayer(t, "db", time.Now())
		f := startFakeOCIRegistry(t, layer)
		var blobs atomic.Int32
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			blobs.Add(1)
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write(layer)
		})
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		updater := NewUpdater(context.Background(), cfg, cacheDir, NewMemoryStateStore())

		second := make(chan UpdateResults)
		go func() {
			time.Sleep(50 * time.Millisecond) // join while the first run downloads
			results, err := updater.UpdateNow(context.Background())
			assert.NoError(t, err)
			second <- results
		}()
		first, err := updater.UpdateNow(context.Background())
		require.NoError(t, err)

		assert.True(t, first.DB.Installed)
		assert.Equal(t, first, <-second)
		assert.Equal(t, int32(1), blobs.Load())
	})

	t.Run("a caller that stops waiting does not stop the run", func(t *testing.T) {
		cacheDir := t.TempDir()
		layer := dbLayer(t, "db", time.Now())
		f := startFakeOCIRegistry(t, layer)
		var blobs atomic.Int32
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			blobs.Add(1)
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write(layer)
		})
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		updater := NewUpdater(context.Background(), cfg, cacheDir, NewMemoryStateStore())

		waitCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := updater.UpdateNow(waitCtx)

		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, time.Since(start), 250*time.Millisecond)

		results, err := updater.UpdateNow(context.Background())
		require.NoError(t, err)
		assert.True(t, results.DB.Installed, "the run went on and this call joined it")
		assert.Equal(t, int32(1), blobs.Load())
	})

	t.Run("Java DB is updated only when it has sources", func(t *testing.T) {
		mainDB := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
		javaSource := startFakeJavaRegistry(t, "java db")
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{mainDB.source(t, "direct")}

		withoutJava := t.TempDir()
		results, err := NewUpdater(context.Background(), cfg, withoutJava, NewMemoryStateStore()).UpdateNow(context.Background())
		require.NoError(t, err)
		assert.Nil(t, results.JavaDB)
		assert.False(t, results.Degraded())
		assert.NoDirExists(t, filepath.Join(withoutJava, "java-db-versions"))

		cfg.JavaDBSources = []config.DBSource{javaSource.source(t, "direct")}
		withJava := t.TempDir()
		results, err = NewUpdater(context.Background(), cfg, withJava, NewMemoryStateStore()).UpdateNow(context.Background())
		require.NoError(t, err)
		require.NotNil(t, results.JavaDB)
		assert.True(t, results.JavaDB.Installed)
		assert.True(t, dbPresent(withJava, "java-db", "trivy-java.db"))
	})

	t.Run("a degraded Java DB makes the results degraded", func(t *testing.T) {
		mainDB := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
		refused, _ := startCountingRefuser(t)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{mainDB.source(t, "direct")}
		cfg.JavaDBSources = []config.DBSource{refused}

		results, err := NewUpdater(context.Background(), cfg, t.TempDir(), NewMemoryStateStore()).UpdateNow(context.Background())

		require.NoError(t, err)
		assert.Equal(t, ModeNormal, results.DB.Mode)
		assert.Equal(t, ModeDegraded, results.JavaDB.Mode)
		assert.True(t, results.Degraded())
	})
}

// TestUpdater_InstalledDigestFromDisk: the installed digest is read from disk, so a
// new updater with empty state over an existing install does not download again.
func TestUpdater_InstalledDigestFromDisk(t *testing.T) {
	cacheDir := t.TempDir()
	f := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
	_, blobs := countRequests(f)
	cfg := updateConfig
	cfg.DBSources = []config.DBSource{f.source(t, "direct")}

	first, err := NewUpdater(context.Background(), cfg, cacheDir, NewMemoryStateStore()).UpdateNow(context.Background())
	require.NoError(t, err)
	require.True(t, first.DB.Installed)

	// A restart: new updater, new empty state store, same cache directory.
	store := NewMemoryStateStore()
	second, err := NewUpdater(context.Background(), cfg, cacheDir, store).UpdateNow(context.Background())
	require.NoError(t, err)

	assert.False(t, second.DB.Installed)
	assert.Equal(t, int32(1), blobs.Load(), "no second download")
	assert.False(t, second.DB.ConfirmedCurrentAt.IsZero(), "the equal digest confirms the DB")
	state, err := store.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, ModeNormal, state.Mode)
	assert.Equal(t, f.manifestDigest, state.ManifestDigest)
}
