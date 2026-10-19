package dbmgr

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

var updateConfig = func() config.Config {
	cfg := testConfig
	cfg.DBDownloadTimeout = 5 * time.Second
	cfg.JavaDBDownloadTimeout = 5 * time.Second
	cfg.DBDownloadStallTimeout = time.Second
	cfg.DBAgeWarn = 7 * 24 * time.Hour
	return cfg
}()

// dbLayer builds a DB layer whose metadata.json has the given UpdatedAt.
func dbLayer(t *testing.T, content string, updatedAt time.Time) []byte {
	return makeLayer(t,
		"trivy.db", content,
		"metadata.json", `{"Version":2,"UpdatedAt":"`+updatedAt.UTC().Format(time.RFC3339Nano)+`"}`,
	)
}

// refusedSource is a source whose port is closed, so its pre-check fails with tcp_refused.
func refusedSource(t *testing.T) config.DBSource {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return directSource(t, addr)
}

func sourceClasses(result UpdateResult) []string {
	var classes []string
	for _, source := range result.Sources {
		classes = append(classes, source.FailureClass)
	}
	return classes
}

func TestUpdate(t *testing.T) {
	now := time.Now()

	t.Run("first source installs the DB, the next run finds it up to date", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "db v1", now))
		f.requireToken = true
		f.redirectBlobs = true
		sources := []config.DBSource{f.source(t, "direct"), refusedSource(t)}

		result := update(testContext(t), updateConfig, cacheDir, trivyDB, sources)

		assert.Equal(t, ModeNormal, result.Mode)
		assert.True(t, result.Installed)
		assert.Equal(t, sources[0].String(), result.ActiveSource)
		assert.Equal(t, f.manifestDigest, result.ManifestDigest)
		assert.WithinDuration(t, time.Now(), result.UpstreamCheckedAt, 5*time.Second)
		assert.Equal(t, now.UTC().Truncate(time.Second), result.Metadata.UpdatedAt.UTC().Truncate(time.Second))
		require.Len(t, result.Sources, 1, "the loop stops after an install")
		assert.True(t, result.Sources[0].Installed)
		assert.Equal(t, "db v1", readDB(t, cacheDir))
		assert.Equal(t, f.manifestDigest, InstalledDigest(cacheDir, "db"))

		again := update(testContext(t), updateConfig, cacheDir, trivyDB, sources)

		assert.Equal(t, ModeNormal, again.Mode)
		assert.False(t, again.Installed)
		require.Len(t, again.Sources, 1, "the loop stops when the digest is unchanged")
		assert.True(t, again.Sources[0].Answered)
		assert.Equal(t, f.manifestDigest, again.ManifestDigest)
		assert.False(t, again.ConfirmedCurrentAt.IsZero(), "same digest confirms the DB is current")
		assert.False(t, again.NewerAvailable)
	})

	t.Run("failed pre-check falls back to the next source", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "db from second source", now))
		sources := []config.DBSource{refusedSource(t), f.source(t, "direct")}

		result := update(testContext(t), updateConfig, cacheDir, trivyDB, sources)

		assert.Equal(t, ModeNormal, result.Mode)
		assert.True(t, result.Installed)
		assert.Equal(t, []string{"tcp_refused", ""}, sourceClasses(result))
		assert.False(t, result.Sources[0].Answered)
		assert.Equal(t, sources[1].String(), result.ActiveSource)
		assert.Equal(t, "db from second source", readDB(t, cacheDir))
	})

	t.Run("failed download falls back to the next source", func(t *testing.T) {
		cacheDir := t.TempDir()
		broken := startFakeOCIRegistry(t, dbLayer(t, "db", now))
		serveBlob(broken, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not the layer")) })
		good := startFakeOCIRegistry(t, dbLayer(t, "good db", now))
		sources := []config.DBSource{broken.source(t, "direct"), good.source(t, "direct")}
		logs := captureLogs(t)

		result := update(testContext(t), updateConfig, cacheDir, trivyDB, sources)

		assert.True(t, result.Installed)
		// The DB source selection is logged (DEMAND section 12).
		assert.Contains(t, logs.String(), `"msg":"DB source selected","db":"db","source":"`+sources[0].String())
		assert.Contains(t, logs.String(), `"msg":"DB source selected","db":"db","source":"`+sources[1].String())
		assert.Contains(t, logs.String(), `"msg":"DB installed","db":"db","source":"`+sources[1].String())
		assert.Equal(t, []string{"download_error", ""}, sourceClasses(result))
		assert.True(t, result.Sources[0].Answered, "the broken source did answer the upstream check")
		assert.Equal(t, "good db", readDB(t, cacheDir))
		assert.Len(t, versionNames(t, cacheDir), 1, "the failed download left no version behind")
	})

	t.Run("a mirror that is behind is installed: no downgrade guard", func(t *testing.T) {
		cacheDir := t.TempDir()
		newer := startFakeOCIRegistry(t, dbLayer(t, "newer db", now))
		require.True(t, update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{newer.source(t, "direct")}).Installed)

		older := startFakeOCIRegistry(t, dbLayer(t, "older db", now.Add(-6*time.Hour)))
		result := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{older.source(t, "direct")})

		assert.True(t, result.Installed)
		assert.Equal(t, "older db", readDB(t, cacheDir))
	})

	t.Run("no source answered: degraded, one ERROR, old DB kept", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "db v1", now))
		require.True(t, update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{f.source(t, "direct")}).Installed)
		logs := captureLogs(t)

		sources := []config.DBSource{refusedSource(t), refusedSource(t)}
		result := update(testContext(t), updateConfig, cacheDir, trivyDB, sources)

		assert.Equal(t, ModeDegraded, result.Mode)
		assert.False(t, result.Installed)
		assert.Empty(t, result.ActiveSource)
		assert.True(t, result.UpstreamCheckedAt.IsZero())
		assert.True(t, result.ConfirmedCurrentAt.IsZero())
		assert.False(t, result.NewerAvailable, "says nothing; the stored flag is kept")
		assert.Equal(t, []string{"tcp_refused", "tcp_refused"}, sourceClasses(result))
		assert.Equal(t, f.manifestDigest, result.ManifestDigest, "the old DB stays active")
		assert.Equal(t, "db v1", readDB(t, cacheDir))

		assert.Equal(t, 1, strings.Count(logs.String(), `"level":"ERROR"`))
		assert.Contains(t, logs.String(), `"msg":"all DB sources failed, scanning with existing DB","db":"db","db_present":true`)
		assert.Contains(t, logs.String(), sources[0].String()+": tcp_refused; "+sources[1].String()+": tcp_refused")
	})

	t.Run("newer DB offered but nothing installed: degraded and stale until a later success", func(t *testing.T) {
		cacheDir := t.TempDir()
		good := startFakeOCIRegistry(t, dbLayer(t, "db v1", now))
		first := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{good.source(t, "direct")})
		require.True(t, first.Installed)
		assert.Equal(t, FreshnessOK, Freshness(first.NewerAvailable, first.ConfirmedCurrentAt, time.Hour, time.Now()))

		brokenA := startFakeOCIRegistry(t, dbLayer(t, "db v2", now))
		serveBlob(brokenA, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not the layer")) })
		brokenB := startFakeOCIRegistry(t, dbLayer(t, "db v2b", now))
		serveBlob(brokenB, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
		logs := captureLogs(t)

		failed := update(testContext(t), updateConfig, cacheDir, trivyDB,
			[]config.DBSource{brokenA.source(t, "direct"), brokenB.source(t, "direct")})

		assert.Equal(t, ModeDegraded, failed.Mode)
		assert.True(t, failed.NewerAvailable)
		assert.False(t, failed.Installed)
		assert.False(t, failed.UpstreamCheckedAt.IsZero(), "sources answered, so last_upstream_check_at is set")
		assert.True(t, failed.ConfirmedCurrentAt.IsZero(), "nothing was confirmed current")
		assert.Equal(t, []string{"download_error", "download_error"}, sourceClasses(failed))
		assert.Equal(t, "db v1", readDB(t, cacheDir), "scans keep the old DB")
		assert.Equal(t, 1, strings.Count(logs.String(), `"level":"ERROR"`))
		assert.Contains(t, logs.String(), `"msg":"newer DB available but could not be installed"`)
		assert.Contains(t, logs.String(), brokenA.source(t, "direct").String()+": download_error; "+brokenB.source(t, "direct").String()+": download_error")
		assert.NotContains(t, logs.String(), "all DB sources failed")

		// Stale while the flag is set, even when the last confirmation is recent.
		assert.Equal(t, FreshnessStale, Freshness(failed.NewerAvailable, first.ConfirmedCurrentAt, 24*time.Hour, time.Now()))

		fixed := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{brokenA.source(t, "direct"), good.source(t, "direct")})

		assert.Equal(t, ModeNormal, fixed.Mode)
		assert.False(t, fixed.NewerAvailable, "cleared by the confirmed-current check")
		assert.False(t, fixed.ConfirmedCurrentAt.IsZero())
		assert.Equal(t, FreshnessOK, Freshness(fixed.NewerAvailable, fixed.ConfirmedCurrentAt, time.Hour, time.Now()))
	})

	t.Run("DB without UpdatedAt or with the wrong layer type is not installed", func(t *testing.T) {
		cacheDir := t.TempDir()
		noUpdatedAt := startFakeOCIRegistry(t, makeLayer(t, "trivy.db", "db", "metadata.json", `{"Version":2}`))
		javaLayer := startFakeOCIRegistry(t, dbLayer(t, "db", now))
		javaLayer.manifest = []byte(strings.Replace(string(javaLayer.manifest), trivyDB.MediaType,
			"application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip", 1))
		javaLayer.manifestDigest = digestOf(javaLayer.manifest)

		result := update(testContext(t), updateConfig, cacheDir, trivyDB,
			[]config.DBSource{noUpdatedAt.source(t, "direct"), javaLayer.source(t, "direct")})

		assert.False(t, result.Installed)
		assert.Equal(t, []string{"download_error", "download_error"}, sourceClasses(result))
		assert.Contains(t, result.Sources[0].Error, "has no UpdatedAt")
		assert.Equal(t, "manifest has no layer of type "+trivyDB.MediaType, result.Sources[1].Error)
		assert.False(t, dbPresent(cacheDir, "db", "trivy.db"))
	})

	t.Run("old DB logs the age WARN with the active source", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "old db", now.Add(-10*24*time.Hour)))
		logs := captureLogs(t)

		result := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{f.source(t, "direct")})

		require.True(t, result.Installed, "an old DB is still installed")
		assert.Contains(t, logs.String(), `"level":"WARN","msg":"DB is older than SCANNER_DB_AGE_WARN","db":"db","db_age":"240h0m0s"`)
		assert.Contains(t, logs.String(), `"active_source":"`+result.ActiveSource+`"`)
	})

	t.Run("fresh DB has no age WARN", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "db", now))
		logs := captureLogs(t)

		update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{f.source(t, "direct")})

		assert.NotContains(t, logs.String(), "SCANNER_DB_AGE_WARN")
	})

	t.Run("secrets do not reach the update logs or results", func(t *testing.T) {
		cacheDir := t.TempDir()
		f := startFakeOCIRegistry(t, dbLayer(t, "db", now))
		f.requireToken = true
		proxy := startSOCKS5Proxy(t, "user", "s3cret")
		logs := captureLogs(t)

		result := update(testContext(t), updateConfig, cacheDir, trivyDB,
			[]config.DBSource{f.source(t, "socks5://user:s3cret@"+proxy.addr)})

		require.True(t, result.Installed)
		assertNoSecretsInLogs(t, logs.String())
		assert.NotContains(t, result.ActiveSource, "s3cret")
	})
}

// startFakeJavaRegistry serves a Java DB layer: Java file name and media type.
func startFakeJavaRegistry(t *testing.T, content string) *fakeOCIRegistry {
	f := startFakeOCIRegistry(t, makeLayer(t,
		"trivy-java.db", content,
		"metadata.json", `{"Version":1,"UpdatedAt":"`+time.Now().UTC().Format(time.RFC3339Nano)+`"}`,
	))
	f.manifest = []byte(strings.Replace(string(f.manifest), trivyDB.MediaType, javaDB.MediaType, 1))
	f.manifestDigest = digestOf(f.manifest)
	return f
}

func TestUpdate_JavaDB(t *testing.T) {
	now := time.Now()

	t.Run("Java DB is installed next to the main DB with the same flow", func(t *testing.T) {
		cacheDir := t.TempDir()
		mainDB := startFakeOCIRegistry(t, dbLayer(t, "main db", now))
		javaSource := startFakeJavaRegistry(t, "java db")

		mainResult := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{mainDB.source(t, "direct")})
		javaResult := update(testContext(t), updateConfig, cacheDir, javaDB,
			[]config.DBSource{refusedSource(t), javaSource.source(t, "direct")})

		require.True(t, mainResult.Installed)
		require.True(t, javaResult.Installed)
		assert.Equal(t, []string{"tcp_refused", ""}, sourceClasses(javaResult), "the Java DB uses the same fallback")
		assert.Equal(t, "main db", readDB(t, cacheDir))
		assert.True(t, dbPresent(cacheDir, "java-db", "trivy-java.db"))
		assert.Equal(t, javaSource.manifestDigest, InstalledDigest(cacheDir, "java-db"))
		assert.Equal(t, mainDB.manifestDigest, InstalledDigest(cacheDir, "db"))
		assert.Equal(t, 1, javaResult.Metadata.Version)
	})

	t.Run("the main DB layer is not accepted as a Java DB", func(t *testing.T) {
		cacheDir := t.TempDir()
		mainDB := startFakeOCIRegistry(t, dbLayer(t, "main db", now))

		result := update(testContext(t), updateConfig, cacheDir, javaDB, []config.DBSource{mainDB.source(t, "direct")})

		assert.False(t, result.Installed)
		assert.Equal(t, "manifest has no layer of type "+javaDB.MediaType, result.Sources[0].Error)
		assert.False(t, dbPresent(cacheDir, "java-db", "trivy-java.db"))
	})

	t.Run("Java seed is installed from its own seed directory", func(t *testing.T) {
		cacheDir := t.TempDir()
		seedDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(seedDir, "trivy-java.db"), []byte("java seed"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(seedDir, "metadata.json"), []byte("{}"), 0o644))

		installed, err := installSeed(cacheDir, javaDB.Name, seedDir, javaDB.Files)

		require.NoError(t, err)
		assert.True(t, installed)
		assert.True(t, dbPresent(cacheDir, "java-db", "trivy-java.db"))
		assert.False(t, dbPresent(cacheDir, "db", "trivy.db"))
	})
}

// TestUpdate_DownloadFailuresFallBack is the P3-9 list at the update level: each
// broken download fails its source and the next source is installed, in bounded time.
func TestUpdate_DownloadFailuresFallBack(t *testing.T) {
	now := time.Now()
	layer := dbLayer(t, strings.Repeat("broken source db ", 2000), now)

	testCases := []struct {
		name          string
		blob          http.HandlerFunc
		expectedError string
	}{
		{
			// Size or digest mismatch; the exact digest error is tested in TestDownloadDB.
			name:          "different content",
			blob:          func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(dbLayer(t, "other", now)) },
			expectedError: "",
		},
		{
			name:          "truncated",
			blob:          func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(layer[:len(layer)/2]) },
			expectedError: "unexpected EOF",
		},
		{
			name: "hang mid-download",
			blob: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(layer[:len(layer)/2])
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			},
			expectedError: "download stalled",
		},
		{
			name:          "server error",
			blob:          func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) },
			expectedError: "returned status 502",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			broken := startFakeOCIRegistry(t, layer)
			serveBlob(broken, tc.blob)
			good := startFakeOCIRegistry(t, dbLayer(t, "good db", now))

			cfg := updateConfig
			cfg.DBDownloadStallTimeout = 200 * time.Millisecond
			start := time.Now()
			result := update(testContext(t), cfg, cacheDir, trivyDB,
				[]config.DBSource{broken.source(t, "direct"), good.source(t, "direct")})

			assert.Less(t, time.Since(start), 3*time.Second)
			assert.Equal(t, ModeNormal, result.Mode)
			assert.True(t, result.Installed)
			assert.Equal(t, []string{"download_error", ""}, sourceClasses(result))
			assert.Contains(t, result.Sources[0].Error, tc.expectedError)
			assert.Equal(t, good.source(t, "direct").String(), result.ActiveSource)
			assert.Equal(t, "good db", readDB(t, cacheDir))
			assert.Len(t, versionNames(t, cacheDir), 1, "the broken download left nothing behind")
		})
	}
}

func TestUpdate_JavaDBDownloadTimeout(t *testing.T) {
	f := startFakeJavaRegistry(t, "java db")

	// A Trivy DB cap that is already over must not affect the Java DB, which has its own.
	cfg := updateConfig
	cfg.DBDownloadTimeout = time.Nanosecond
	cfg.JavaDBDownloadTimeout = 5 * time.Second

	result := update(testContext(t), cfg, t.TempDir(), javaDB, []config.DBSource{f.source(t, "direct")})

	assert.True(t, result.Installed, "%+v", result.Sources)

	cfg.JavaDBDownloadTimeout = time.Nanosecond
	result = update(testContext(t), cfg, t.TempDir(), javaDB, []config.DBSource{f.source(t, "direct")})

	assert.False(t, result.Installed)
	assert.Equal(t, []string{"download_error"}, sourceClasses(result))
	assert.Contains(t, result.Sources[0].Error, "download exceeded the overall limit")
}

// TestUpdate_InstallWriteError: a write error on our disk (here a full disk, injected)
// fails as install_error, keeps the old DB, leaves no partial directory, and gives
// degraded with newer_available.
func TestUpdate_InstallWriteError(t *testing.T) {
	now := time.Now()
	cacheDir := t.TempDir()
	v1 := startFakeOCIRegistry(t, dbLayer(t, "db v1", now))
	require.True(t, update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{v1.source(t, "direct")}).Installed)
	versionsBefore := versionNames(t, cacheDir)
	v2 := startFakeOCIRegistry(t, dbLayer(t, strings.Repeat("db v2 ", 1000), now))
	realCreateFile := createFile
	fakeFullDisk(t, 100)

	result := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{v2.source(t, "direct")})

	assert.Equal(t, []string{"install_error"}, sourceClasses(result))
	assert.Contains(t, result.Sources[0].Error, "no space left on device")
	assert.Equal(t, ModeDegraded, result.Mode)
	assert.True(t, result.NewerAvailable)
	assert.False(t, result.Installed)
	assert.Equal(t, "db v1", readDB(t, cacheDir), "the old DB is kept")
	assert.Equal(t, v1.manifestDigest, InstalledDigest(cacheDir, "db"))
	assert.Equal(t, versionsBefore, versionNames(t, cacheDir), "no partial directory")

	// Once the disk has space again, the next run installs and clears the flag.
	createFile = realCreateFile
	fixed := update(testContext(t), updateConfig, cacheDir, trivyDB, []config.DBSource{v2.source(t, "direct")})
	assert.True(t, fixed.Installed)
	assert.False(t, fixed.NewerAvailable)
	assert.Equal(t, strings.Repeat("db v2 ", 1000), readDB(t, cacheDir))
}
