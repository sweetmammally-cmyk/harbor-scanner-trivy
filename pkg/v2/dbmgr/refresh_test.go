package dbmgr

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

func TestUpdater_RefreshForScan(t *testing.T) {
	// setup returns an updater over a fake registry whose DB is already installed,
	// its store, and a counter of manifest requests (each run asks twice).
	setup := func(t *testing.T) (*Updater, *MemoryStateStore, func() int32) {
		f := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
		manifests, _ := countRequests(f)
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		cfg.OnDemandRefreshWait = 5 * time.Second
		cfg.OnDemandRefreshMinGap = time.Minute
		store := NewMemoryStateStore()
		updater := NewUpdater(context.Background(), cfg, t.TempDir(), store)
		_, err := updater.UpdateNow(context.Background())
		require.NoError(t, err)
		return updater, store, manifests.Load
	}
	// confirmedAgo makes the stored DB look confirmed some time ago.
	confirmedAgo := func(t *testing.T, store *MemoryStateStore, ago time.Duration, mode string) {
		state, err := store.Get(context.Background(), "db")
		require.NoError(t, err)
		state.LastConfirmedCurrentAt = time.Now().Add(-ago)
		state.Mode = mode
		require.NoError(t, store.Save(context.Background(), "db", state))
	}

	t.Run("fresh DB: no refresh", func(t *testing.T) {
		updater, _, manifests := setup(t)
		before := manifests()

		state, freshness, err := updater.RefreshForScan(context.Background(), time.Hour)

		require.NoError(t, err)
		assert.Equal(t, FreshnessOK, freshness)
		assert.Equal(t, ModeNormal, state.Mode)
		assert.Equal(t, before, manifests())
	})

	t.Run("stale DB: refresh, then fresh", func(t *testing.T) {
		updater, store, manifests := setup(t)
		confirmedAgo(t, store, 2*time.Hour, ModeNormal)
		updater.lastFinished = time.Time{} // no recent run
		before := manifests()

		state, freshness, err := updater.RefreshForScan(context.Background(), time.Hour)

		require.NoError(t, err)
		assert.Equal(t, FreshnessOK, freshness)
		assert.WithinDuration(t, time.Now(), state.LastConfirmedCurrentAt, 5*time.Second)
		assert.Greater(t, manifests(), before, "a run was made")
	})

	t.Run("degraded: no refresh, stays stale", func(t *testing.T) {
		updater, store, manifests := setup(t)
		confirmedAgo(t, store, 2*time.Hour, ModeDegraded)
		updater.lastFinished = time.Time{}
		before := manifests()

		_, freshness, err := updater.RefreshForScan(context.Background(), time.Hour)

		require.NoError(t, err)
		assert.Equal(t, FreshnessStale, freshness)
		assert.Equal(t, before, manifests(), "the retry interval governs")
	})

	t.Run("a run finished within the min gap is reused", func(t *testing.T) {
		updater, store, manifests := setup(t) // setup's run just finished
		confirmedAgo(t, store, 2*time.Hour, ModeNormal)
		before := manifests()

		_, freshness, err := updater.RefreshForScan(context.Background(), time.Hour)

		require.NoError(t, err)
		assert.Equal(t, FreshnessStale, freshness)
		assert.Equal(t, before, manifests(), "no new run within the gap")
	})

	t.Run("a slow refresh is not waited for, it finishes in the background", func(t *testing.T) {
		cacheDir := t.TempDir()
		layer := dbLayer(t, "db", time.Now())
		f := startFakeOCIRegistry(t, layer)
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write(layer)
		})
		cfg := updateConfig
		cfg.DBSources = []config.DBSource{f.source(t, "direct")}
		cfg.OnDemandRefreshWait = 50 * time.Millisecond
		store := NewMemoryStateStore()
		updater := NewUpdater(context.Background(), cfg, cacheDir, store)

		start := time.Now()
		_, freshness, err := updater.RefreshForScan(context.Background(), time.Hour)

		require.NoError(t, err)
		assert.Equal(t, FreshnessStale, freshness, "the scan proceeds with the current DB")
		assert.Less(t, time.Since(start), 250*time.Millisecond)
		require.Eventually(t, func() bool { return InstalledDigest(cacheDir, "db") == f.manifestDigest },
			5*time.Second, 10*time.Millisecond, "the refresh went on")
		require.Eventually(t, func() bool {
			state, _ := store.Get(context.Background(), "db")
			return state.Freshness(time.Hour, time.Now()) == FreshnessOK
		}, 5*time.Second, 10*time.Millisecond)
	})

	t.Run("store error is returned", func(t *testing.T) {
		updater := NewUpdater(context.Background(), updateConfig, t.TempDir(), failingStore{})

		_, freshness, err := updater.RefreshForScan(context.Background(), time.Hour)

		assert.EqualError(t, err, "store down")
		assert.Equal(t, FreshnessStale, freshness)
	})
}
