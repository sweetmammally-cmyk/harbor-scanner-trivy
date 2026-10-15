package dbmgr

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

func TestDBState_Apply(t *testing.T) {
	checked := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	confirmed := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	stored := DBState{
		Mode:                   ModeDegraded,
		ActiveSource:           "mirror|direct",
		ManifestDigest:         "sha256:old",
		LastUpstreamCheckAt:    checked,
		LastConfirmedCurrentAt: confirmed,
		NewerAvailable:         true,
		InstalledAt:            confirmed,
	}

	t.Run("no source answered keeps what we knew about upstream", func(t *testing.T) {
		state := stored.apply(UpdateResult{Mode: ModeDegraded, ManifestDigest: "sha256:old",
			Sources: []SourceResult{{Source: "mirror|direct", FailureClass: "tcp_timeout"}}})

		assert.Equal(t, ModeDegraded, state.Mode)
		assert.True(t, state.NewerAvailable, "a run without answers does not clear the flag")
		assert.Equal(t, "mirror|direct", state.ActiveSource)
		assert.Equal(t, checked, state.LastUpstreamCheckAt)
		assert.Equal(t, confirmed, state.LastConfirmedCurrentAt)
		assert.Equal(t, "tcp_timeout", state.LastSources[0].FailureClass)
	})

	t.Run("newer offered but not installed sets the flag", func(t *testing.T) {
		now := checked.Add(time.Hour)
		state := DBState{}.apply(UpdateResult{Mode: ModeDegraded, ActiveSource: "ghcr|direct",
			UpstreamCheckedAt: now, NewerAvailable: true})

		assert.True(t, state.NewerAvailable)
		assert.Equal(t, now, state.LastUpstreamCheckAt)
		assert.Equal(t, "ghcr|direct", state.ActiveSource)
		assert.True(t, state.LastConfirmedCurrentAt.IsZero())
	})

	t.Run("confirmed current clears the flag", func(t *testing.T) {
		now := checked.Add(time.Hour)
		state := stored.apply(UpdateResult{Mode: ModeNormal, ActiveSource: "ghcr|direct",
			UpstreamCheckedAt: now, ConfirmedCurrentAt: now, ManifestDigest: "sha256:old"})

		assert.Equal(t, ModeNormal, state.Mode)
		assert.False(t, state.NewerAvailable)
		assert.Equal(t, now, state.LastConfirmedCurrentAt)
		assert.Equal(t, confirmed, state.InstalledAt, "nothing was installed")
	})

	t.Run("install clears the flag and records the install time", func(t *testing.T) {
		now := checked.Add(time.Hour)
		metadata := Metadata{Version: 2, UpdatedAt: now.Add(-time.Hour)}
		state := stored.apply(UpdateResult{Mode: ModeNormal, ActiveSource: "ghcr|direct", Installed: true,
			UpstreamCheckedAt: now, ConfirmedCurrentAt: now, ManifestDigest: "sha256:new", Metadata: metadata})

		assert.False(t, state.NewerAvailable)
		assert.Equal(t, now, state.InstalledAt)
		assert.Equal(t, "sha256:new", state.ManifestDigest)
		assert.Equal(t, metadata, state.Metadata)
	})
}

func TestMemoryStateStore(t *testing.T) {
	store := NewMemoryStateStore()

	state, err := store.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, DBState{}, state, "no state yet")

	require.NoError(t, store.Save(context.Background(), "db", DBState{Mode: ModeNormal}))
	state, err = store.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, ModeNormal, state.Mode)

	javaState, err := store.Get(context.Background(), "java-db")
	require.NoError(t, err)
	assert.Equal(t, DBState{}, javaState, "each DB has its own state")
}

func TestUpdater_SavesState(t *testing.T) {
	now := time.Now()
	cacheDir := t.TempDir()
	store := NewMemoryStateStore()
	layer := dbLayer(t, "db", now)
	f := startFakeOCIRegistry(t, layer)
	var blobFails atomic.Bool
	blobFails.Store(true)
	serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
		if blobFails.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(layer)
	})
	updateOnce := func(sources ...config.DBSource) DBState {
		cfg := updateConfig
		cfg.DBSources = sources
		_, err := NewUpdater(context.Background(), cfg, cacheDir, store).UpdateNow(context.Background())
		require.NoError(t, err)
		state, err := store.Get(context.Background(), "db")
		require.NoError(t, err)
		return state
	}

	// 1. A newer DB is offered but the download fails.
	state := updateOnce(f.source(t, "direct"))
	assert.Equal(t, ModeDegraded, state.Mode)
	assert.True(t, state.NewerAvailable)
	assert.Equal(t, f.source(t, "direct").String(), state.ActiveSource)
	assert.Equal(t, FreshnessStale, Freshness(state.NewerAvailable, state.LastConfirmedCurrentAt, time.Hour, time.Now()))
	checkedAt := state.LastUpstreamCheckAt
	require.False(t, checkedAt.IsZero())

	// 2. No source answers: the flag and what we knew about upstream are kept.
	state = updateOnce(refusedSource(t))
	assert.Equal(t, ModeDegraded, state.Mode)
	assert.True(t, state.NewerAvailable)
	assert.Equal(t, checkedAt, state.LastUpstreamCheckAt)
	assert.Equal(t, f.source(t, "direct").String(), state.ActiveSource)
	assert.Equal(t, "tcp_refused", state.LastSources[0].FailureClass)

	// 3. The download works again: installed, flag cleared, fresh.
	blobFails.Store(false)
	state = updateOnce(f.source(t, "direct"))
	assert.Equal(t, ModeNormal, state.Mode)
	assert.False(t, state.NewerAvailable)
	assert.False(t, state.InstalledAt.IsZero())
	assert.Equal(t, f.manifestDigest, state.ManifestDigest)
	assert.Equal(t, FreshnessOK, Freshness(state.NewerAvailable, state.LastConfirmedCurrentAt, time.Hour, time.Now()))

	javaState, err := store.Get(context.Background(), "java-db")
	require.NoError(t, err)
	assert.Equal(t, DBState{}, javaState, "no Java sources: no Java state")
}

// failingStore is a StateStore whose calls always fail.
type failingStore struct{}

func (failingStore) Get(context.Context, string) (DBState, error) {
	return DBState{}, errors.New("store down")
}

func (failingStore) Save(context.Context, string, DBState) error {
	return errors.New("store down")
}

func TestUpdater_StateStoreError(t *testing.T) {
	f := startFakeOCIRegistry(t, dbLayer(t, "db", time.Now()))
	cfg := updateConfig
	cfg.DBSources = []config.DBSource{f.source(t, "direct")}
	logs := captureLogs(t)

	results, err := NewUpdater(context.Background(), cfg, t.TempDir(), failingStore{}).UpdateNow(context.Background())

	require.NoError(t, err)
	assert.True(t, results.DB.Installed, "the DB update itself does not depend on the store")
	assert.Contains(t, logs.String(), `"level":"ERROR","msg":"saving DB state failed","db":"db","error":"store down"`)
}

func TestDBState_FreshnessAndAge(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	state := DBState{
		LastConfirmedCurrentAt: now.Add(-2 * time.Hour),
		Metadata:               Metadata{UpdatedAt: now.Add(-30 * time.Hour)},
	}

	assert.Equal(t, FreshnessOK, state.Freshness(3*time.Hour, now))
	assert.Equal(t, FreshnessStale, state.Freshness(time.Hour, now), "confirmed 2h ago, request wants 1h")
	assert.Equal(t, 30*time.Hour, state.Age(now))

	state.NewerAvailable = true
	assert.Equal(t, FreshnessStale, state.Freshness(24*time.Hour, now), "newer available is always stale")

	assert.Equal(t, FreshnessStale, DBState{}.Freshness(24*time.Hour, now), "never confirmed")
	assert.Equal(t, time.Duration(0), DBState{}.Age(now), "no metadata, unknown age")
}
