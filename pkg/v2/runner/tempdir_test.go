package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanTempDir: each scan has its own temp directory inside the runner's
// temp root (Trivy's TMPDIR and the output), removed on every ending.
func TestScanTempDir(t *testing.T) {
	t.Run("Trivy's TMPDIR is the scan's own directory; removed after a successful scan", func(t *testing.T) {
		r, _ := newScanRunner(t)
		tmpdirFile := filepath.Join(t.TempDir(), "tmpdir")
		t.Setenv("TRIVY_FAKE_TMPDIR_FILE", tmpdirFile)

		_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

		require.NoError(t, err)
		used, err := os.ReadFile(tmpdirFile)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(used), r.tmpDir+string(filepath.Separator)+"scan-"), string(used))
		assertNoOutputLeft(t, r)
	})

	for name, tc := range map[string]struct {
		mode  string
		setup func(r *Runner)
		class string
	}{
		"Trivy fails":         {mode: "exit", class: FailureExit},
		"Trivy times out":     {mode: "hang", setup: func(r *Runner) { r.cfg.ScanTimeout = 300 * time.Millisecond }, class: FailureTimeout},
		"output too large":    {mode: "huge", setup: func(r *Runner) { t.Setenv("TRIVY_FAKE_SIZE", "2000"); r.cfg.ScanMaxOutput = 1000 }, class: FailureOutputTooLarge},
		"output not readable": {mode: "okslow", class: FailureOutputInvalid},
	} {
		t.Run("removed when "+name, func(t *testing.T) {
			r, _ := newScanRunner(t)
			t.Setenv("TRIVY_FAKE_MODE", tc.mode)
			if tc.setup != nil {
				tc.setup(r)
			}

			_, _, err := r.Scan(context.Background(), "worker-1", queuedScan(), reference)

			assertClass(t, err, tc.class)
			assertNoOutputLeft(t, r)
		})
	}

	t.Run("removed when the scan is killed (lease lost or shutdown)", func(t *testing.T) {
		r, _ := newScanRunner(t)
		t.Setenv("TRIVY_FAKE_MODE", "hang")
		pidFile := filepath.Join(t.TempDir(), "pid")
		t.Setenv("TRIVY_FAKE_CHILD_PID", pidFile)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			require.Eventually(t, func() bool { _, err := os.Stat(pidFile); return err == nil }, 5*time.Second, 10*time.Millisecond)
			cancel()
		}()

		_, _, err := r.Scan(ctx, "worker-1", queuedScan(), reference)

		require.Error(t, err)
		assertNoOutputLeft(t, r)
	})

	t.Run("leftovers are removed at startup", func(t *testing.T) {
		r, _ := newScanRunner(t)
		leftover := filepath.Join(r.tmpDir, "scan-123", "blob")
		require.NoError(t, os.MkdirAll(filepath.Dir(leftover), 0o700))
		require.NoError(t, os.WriteFile(leftover, []byte("half a layer"), 0o600))

		require.NoError(t, r.CleanTemp())

		assertNoOutputLeft(t, r)
		info, err := os.Stat(r.tmpDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir(), "the root stays")
	})
}
