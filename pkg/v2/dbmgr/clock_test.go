package dbmgr

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// fakeClock is a clock the test moves by hand. Run's waits are recorded in waits
// and end only when the test sends on fire.
type fakeClock struct {
	mu      sync.Mutex
	current time.Time
	waits   chan time.Duration
	fire    chan time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{current: start, waits: make(chan time.Duration, 10), fire: make(chan time.Time)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = c.current.Add(d)
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.waits <- d
	return c.fire
}

// nextWait returns the next wait Run asked for.
func (c *fakeClock) nextWait(t *testing.T) time.Duration {
	select {
	case d := <-c.waits:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not wait")
		return 0
	}
}

// runWithClock starts Run with the fake clock and stops it at the end of the test.
func runWithClock(t *testing.T, cfg config.Config, clock *fakeClock) {
	ctx, cancel := context.WithCancel(context.Background())
	updater := NewUpdater(ctx, cfg, t.TempDir(), NewMemoryStateStore())
	updater.now = clock.Now
	updater.after = clock.After
	stopped := make(chan struct{})
	go func() {
		updater.Run()
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
}

func TestUpdater_FakeClock(t *testing.T) {
	t.Run("unset check interval falls back to 3h; degraded uses the 15m retry interval", func(t *testing.T) {
		t.Setenv("SCANNER_DB_CHECK_INTERVAL", "")
		cfg, err := config.GetConfig()
		require.NoError(t, err)
		require.Equal(t, 3*time.Hour, cfg.DBCheckInterval)
		require.Equal(t, 15*time.Minute, cfg.DBRetryInterval)

		layer := dbLayer(t, "db", time.Now())
		f := startFakeOCIRegistry(t, layer)
		var blobCalls atomic.Int32
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			if blobCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway) // first run: newer DB not installed, degraded
				return
			}
			_, _ = w.Write(layer)
		})
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		clock := newFakeClock(time.Now())

		runWithClock(t, cfg, clock)

		assert.Equal(t, 15*time.Minute, clock.nextWait(t), "degraded: retry interval")
		clock.fire <- clock.Now()
		assert.Equal(t, 3*time.Hour, clock.nextWait(t), "after the install: the 3h fallback check interval")
		clock.fire <- clock.Now()
		assert.Equal(t, 3*time.Hour, clock.nextWait(t), "up to date: the check interval again")
		assert.Equal(t, int32(2), blobCalls.Load())
	})

	t.Run("a configured interval with days is used", func(t *testing.T) {
		t.Setenv("SCANNER_DB_CHECK_INTERVAL", "1d")
		cfg, err := config.GetConfig()
		require.NoError(t, err)
		f := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		clock := newFakeClock(time.Now())

		runWithClock(t, cfg, clock)

		assert.Equal(t, 24*time.Hour, clock.nextWait(t))
	})

	t.Run("on-demand min gap follows the clock", func(t *testing.T) {
		f := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
		manifests, _ := countRequests(f)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		cfg.OnDemandRefreshWait = 5 * time.Second
		cfg.OnDemandRefreshMinGap = time.Minute
		clock := newFakeClock(time.Now())
		updater := NewUpdater(context.Background(), cfg, t.TempDir(), NewMemoryStateStore())
		updater.now = clock.Now
		_, err := updater.UpdateNow(context.Background())
		require.NoError(t, err)
		afterFirstRun := manifests.Load()

		// 59s later the DB is stale for a 30s max age, but the last run is within the gap.
		clock.Advance(59 * time.Second)
		_, freshness, err := updater.RefreshForScan(context.Background(), 30*time.Second)
		require.NoError(t, err)
		assert.Equal(t, FreshnessStale, freshness)
		assert.Equal(t, afterFirstRun, manifests.Load(), "within the gap: no run")

		// 61s after the run the gap is over: a refresh runs.
		clock.Advance(2 * time.Second)
		_, _, err = updater.RefreshForScan(context.Background(), 30*time.Second)
		require.NoError(t, err)
		assert.Greater(t, manifests.Load(), afterFirstRun, "after the gap: a run")
	})

	t.Run("freshness turns stale exactly after max age", func(t *testing.T) {
		confirmed := time.Date(2026, 10, 15, 6, 0, 0, 0, time.UTC)
		state := DBState{LastConfirmedCurrentAt: confirmed}
		clock := newFakeClock(confirmed)

		clock.Advance(6 * time.Hour)
		assert.Equal(t, FreshnessOK, state.Freshness(6*time.Hour, clock.Now()))
		clock.Advance(time.Second)
		assert.Equal(t, FreshnessStale, state.Freshness(6*time.Hour, clock.Now()))
	})
}
