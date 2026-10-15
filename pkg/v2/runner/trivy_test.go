package runner

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// fakeTrivy is a stand-in for the trivy binary. TRIVY_FAKE_MODE picks what it
// does; the TRIVY_FAKE_* variables pass Trivy's environment allowlist.
const fakeTrivy = `#!/bin/sh
if [ "$1" = "--version" ]; then
  [ "$TRIVY_FAKE_MODE" = "badversion" ] && { echo "boom" >&2; exit 1; }
  printf 'Version: 0.71.2\nVulnerability DB:\n  Version: 2\n'
  exit 0
fi
out=""
cache=""
prev=""
for a in "$@"; do
  case "$prev" in
    --output) out="$a" ;;
    --cache-dir) cache="$a" ;;
  esac
  prev="$a"
done
[ -n "$TRIVY_FAKE_ARGS_FILE" ] && printf '%s\n' "$@" > "$TRIVY_FAKE_ARGS_FILE"
[ -n "$TRIVY_FAKE_ENV_FILE" ] && env > "$TRIVY_FAKE_ENV_FILE"
case "$TRIVY_FAKE_MODE" in
  ok) printf '{"SchemaVersion":2,"Results":[]}' > "$out" ;;
  fixture) cat "$TRIVY_FAKE_FIXTURE" > "$out" ;;
  okslow) sleep 0.3; printf '%s' "$cache" > "$out" ;;
  slow)
    first=$(cat "$cache/db/trivy.db")
    touch "$TRIVY_FAKE_STARTED"
    while [ ! -e "$TRIVY_FAKE_CONTINUE" ]; do sleep 0.05; done
    second=$(cat "$cache/db/trivy.db")
    printf '%s|%s' "$first" "$second" > "$out" ;;
  hang)
    sleep 300 &
    echo $! > "$TRIVY_FAKE_CHILD_PID"
    wait ;;
  huge) head -c "$TRIVY_FAKE_SIZE" /dev/zero > "$out" ;;
  exit) echo "pulling as $TRIVY_USERNAME with password $TRIVY_PASSWORD failed" >&2; exit 2 ;;
  java) echo "FATAL Fatal error: post analysis error: Unable to initialize the Java DB: Java DB update failed" >&2; exit 1 ;;
  trivytimeout) echo "FATAL Fatal error: scan error: context deadline exceeded" >&2; exit 1 ;;
esac
`

const robotPassword = "s3cret-robot"

// installTestDB installs a Trivy DB version with the given content via dbmgr.
func installTestDB(t *testing.T, cacheDir, dbName, content string) {
	t.Helper()
	versionDir := filepath.Join(cacheDir, dbName+"-versions", "v-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	require.NoError(t, os.MkdirAll(versionDir, 0o755))
	dbFile := "trivy.db"
	if dbName == "java-db" {
		dbFile = "trivy-java.db"
	}
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, dbFile), []byte(content), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "metadata.json"),
		[]byte(`{"Version":2,"UpdatedAt":"2026-10-15T07:10:08Z"}`), 0o644))
	require.NoError(t, dbmgr.InstallDB(cacheDir, dbName, versionDir, "sha256:"+content))
}

// newTestRunner returns a runner using the fake trivy, with an installed DB.
func newTestRunner(t *testing.T) (*Runner, string) {
	t.Helper()
	trivy := filepath.Join(t.TempDir(), "trivy")
	require.NoError(t, os.WriteFile(trivy, []byte(fakeTrivy), 0o755))
	cacheDir := t.TempDir()
	installTestDB(t, cacheDir, "db", "db-v1")
	cfg := config.Config{
		RegistryURL:      "https://harbor.local",
		RegistryUsername: "robot$scanner",
		RegistryPassword: robotPassword,
		ScanTimeout:      10 * time.Second,
		ScanMaxOutput:    1 << 20,
	}
	return NewRunner(cfg, trivy, cacheDir, t.TempDir(), store.NewMemoryPlatforms()), cacheDir
}

const reference = "harbor.local/project/app@sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestRunTrivy_Success(t *testing.T) {
	r, _ := newTestRunner(t)
	t.Setenv("TRIVY_FAKE_MODE", "ok")
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("TRIVY_FAKE_ARGS_FILE", argsFile)

	output, db, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

	require.NoError(t, err)
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, `{"SchemaVersion":2,"Results":[]}`, string(data))
	info, err := os.Stat(output)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the output file is private")
	assert.Equal(t, "sha256:db-v1", db.ManifestDigest)
	assert.Equal(t, time.Date(2026, 10, 15, 7, 10, 8, 0, time.UTC), db.UpdatedAt.UTC())

	args, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"image", "--scanners", "vuln", "--format", "json", "--output", output,
		"--list-all-pkgs=false", "--skip-db-update", "--skip-java-db-update", "--skip-version-check",
		"--image-src", "remote", "--cache-dir", filepath.Join(r.workDir, "worker-1"),
		"--timeout", "9s", "--quiet", reference,
	}, strings.Split(strings.TrimSpace(string(args)), "\n"), "no --severity, scan by digest")
}

func TestRunTrivy_PlainHTTPRegistry(t *testing.T) {
	r, _ := newTestRunner(t)
	r.plainHTTP = true
	t.Setenv("TRIVY_FAKE_MODE", "ok")
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("TRIVY_FAKE_ARGS_FILE", argsFile)

	_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

	require.NoError(t, err)
	args, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	assert.Contains(t, string(args), "--insecure\n")
}

func TestRunTrivy_Environment(t *testing.T) {
	r, _ := newTestRunner(t)
	t.Setenv("TRIVY_FAKE_MODE", "ok")
	envFile := filepath.Join(t.TempDir(), "env")
	t.Setenv("TRIVY_FAKE_ENV_FILE", envFile)
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("TRIVY_FAKE_ARGS_FILE", argsFile)
	// Secrets of the scanner itself must not reach Trivy.
	t.Setenv("SCANNER_MONGO_URI", "mongodb://user:mongo-s3cret@mongo:27017")
	t.Setenv("SCANNER_V2_AUTH_TOKEN", "service-t0ken")
	t.Setenv("SCANNER_REGISTRY_PASSWORD", robotPassword)
	t.Setenv("SOME_OTHER_SECRET", "other-s3cret")
	t.Setenv("TRIVY_PASSWORD", "stale")
	t.Setenv("HTTPS_PROXY", "http://proxy:3128")

	_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

	require.NoError(t, err)
	envData, err := os.ReadFile(envFile)
	require.NoError(t, err)
	env := string(envData)
	assert.NotContains(t, env, "SCANNER_")
	assert.NotContains(t, env, "mongo-s3cret")
	assert.NotContains(t, env, "service-t0ken")
	assert.NotContains(t, env, "other-s3cret")
	assert.NotContains(t, env, "stale")
	assert.Contains(t, env, "TRIVY_USERNAME=robot$scanner\n")
	assert.Contains(t, env, "TRIVY_PASSWORD="+robotPassword+"\n")
	assert.Contains(t, env, "HTTPS_PROXY=http://proxy:3128\n")
	assert.Contains(t, env, "PATH=")

	args, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	assert.NotContains(t, string(args), robotPassword, "credentials never on the command line")
	assert.NotContains(t, string(args), "robot$scanner")
}

func TestRunTrivy_Failures(t *testing.T) {
	t.Run("hard timeout kills Trivy and its children", func(t *testing.T) {
		r, _ := newTestRunner(t)
		r.cfg.ScanTimeout = 300 * time.Millisecond
		t.Setenv("TRIVY_FAKE_MODE", "hang")
		childFile := filepath.Join(t.TempDir(), "child")
		t.Setenv("TRIVY_FAKE_CHILD_PID", childFile)

		start := time.Now()
		_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

		assertClass(t, err, FailureTimeout)
		assert.Less(t, time.Since(start), 3*time.Second)
		data, readErr := os.ReadFile(childFile)
		require.NoError(t, readErr)
		pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
		require.NoError(t, convErr)
		require.Eventually(t, func() bool { return syscall.Kill(pid, 0) == syscall.ESRCH }, 2*time.Second, 20*time.Millisecond,
			"the child process was killed with the process group")
		assertNoOutputLeft(t, r)
	})

	t.Run("Trivy's own timeout", func(t *testing.T) {
		r, _ := newTestRunner(t)
		t.Setenv("TRIVY_FAKE_MODE", "trivytimeout")

		_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

		assertClass(t, err, FailureTimeout)
	})

	t.Run("output larger than the limit", func(t *testing.T) {
		r, _ := newTestRunner(t)
		r.cfg.ScanMaxOutput = 1000
		t.Setenv("TRIVY_FAKE_MODE", "huge")
		t.Setenv("TRIVY_FAKE_SIZE", "2000")

		_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

		assertClass(t, err, FailureOutputTooLarge)
		assert.Contains(t, err.Error(), "Trivy wrote 2000 bytes")
		assertNoOutputLeft(t, r)
	})

	t.Run("exit error keeps a redacted stderr tail", func(t *testing.T) {
		r, _ := newTestRunner(t)
		t.Setenv("TRIVY_FAKE_MODE", "exit")

		_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

		assertClass(t, err, FailureExit)
		assert.Contains(t, err.Error(), "exit status 2")
		assert.Contains(t, err.Error(), "with password xxxxx failed")
		assert.NotContains(t, err.Error(), robotPassword)
		assertNoOutputLeft(t, r)
	})

	t.Run("jars without a Java DB", func(t *testing.T) {
		r, _ := newTestRunner(t)
		t.Setenv("TRIVY_FAKE_MODE", "java")

		_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

		assertClass(t, err, FailureJavaDBMissing)
		assert.Contains(t, err.Error(), "SCANNER_JAVA_DB_SOURCES")
	})

	t.Run("no DB installed: Trivy is not started", func(t *testing.T) {
		r, _ := newTestRunner(t)
		r.cacheDir = t.TempDir()
		t.Setenv("TRIVY_FAKE_MODE", "ok")
		argsFile := filepath.Join(t.TempDir(), "args")
		t.Setenv("TRIVY_FAKE_ARGS_FILE", argsFile)

		_, _, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)

		assertClass(t, err, FailureDBMissing)
		assert.NoFileExists(t, argsFile)
	})
}

func TestRunTrivy_DBSwapDuringScan(t *testing.T) {
	r, cacheDir := newTestRunner(t)
	t.Setenv("TRIVY_FAKE_MODE", "slow")
	started := filepath.Join(t.TempDir(), "started")
	proceed := filepath.Join(t.TempDir(), "continue")
	t.Setenv("TRIVY_FAKE_STARTED", started)
	t.Setenv("TRIVY_FAKE_CONTINUE", proceed)

	type result struct {
		output string
		db     DBInfo
		err    error
	}
	done := make(chan result)
	go func() {
		output, db, err := r.runTrivy(context.Background(), slog.Default(), "worker-1", reference)
		done <- result{output, db, err}
	}()
	require.Eventually(t, func() bool { _, err := os.Stat(started); return err == nil }, 5*time.Second, 10*time.Millisecond)

	// Two installs during the scan: without the pin the scan's version would be removed.
	installTestDB(t, cacheDir, "db", "db-v2")
	installTestDB(t, cacheDir, "db", "db-v3")
	require.NoError(t, os.WriteFile(proceed, nil, 0o644))
	res := <-done

	require.NoError(t, res.err)
	data, err := os.ReadFile(res.output)
	require.NoError(t, err)
	assert.Equal(t, "db-v1|db-v1", string(data), "the scan read the same DB version from start to end")
	assert.Equal(t, "sha256:db-v1", res.db.ManifestDigest)

	// Unpinned now: the next install removes it.
	installTestDB(t, cacheDir, "db", "db-v4")
	versions, err := os.ReadDir(filepath.Join(cacheDir, "db-versions"))
	require.NoError(t, err)
	assert.Len(t, versions, 2, "only the current and the previous version remain")
}

func TestRunTrivy_ConcurrentWorkers(t *testing.T) {
	r, _ := newTestRunner(t)
	t.Setenv("TRIVY_FAKE_MODE", "okslow")

	var wg sync.WaitGroup
	outputs := make([]string, 2)
	errs := make([]error, 2)
	start := time.Now()
	for i := range outputs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outputs[i], _, errs[i] = r.runTrivy(context.Background(), slog.Default(), "worker-"+strconv.Itoa(i), reference)
		}()
	}
	wg.Wait()

	assert.Less(t, time.Since(start), 550*time.Millisecond, "the two Trivy processes ran at the same time")
	for i := range outputs {
		require.NoError(t, errs[i])
		data, err := os.ReadFile(outputs[i])
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(r.workDir, "worker-"+strconv.Itoa(i)), string(data), "each worker has its own cache")
	}
}

func TestTrivyTimeout(t *testing.T) {
	assert.Equal(t, 9*time.Second, trivyTimeout(10*time.Second))
	assert.Equal(t, 9*time.Minute+30*time.Second, trivyTimeout(10*time.Minute), "at most 30s below")
}

func assertClass(t *testing.T, err error, class string) {
	t.Helper()
	scanErr, ok := err.(*ScanError)
	require.True(t, ok, "%v", err)
	assert.Equal(t, class, scanErr.Class, scanErr.Detail)
}

// assertNoOutputLeft checks that no output file was left in any worker directory.
func assertNoOutputLeft(t *testing.T, r *Runner) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(r.workDir, "*", "scan-*.json"))
	require.NoError(t, err)
	assert.Empty(t, files)
}
