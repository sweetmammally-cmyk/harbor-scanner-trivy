package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// healthWorld is what the health check sees; tests change it step by step.
type healthWorld struct {
	storeUp bool
	workers int
	stats   queue.Stats
	recent  queue.Recent
}

func newHealthHandler(world *healthWorld) *Handler {
	cfg := config.Config{AuthToken: testToken, MaxInflight: 4, InstanceID: "scanner-1", DBMaxAgeDefault: 6 * time.Hour,
		DBAgeWarn: 7 * 24 * time.Hour, HealthQueueStuckAfter: 10 * time.Minute, MongoOperationTimeout: time.Second}
	return NewHandler(cfg, Deps{
		DBState:         dbmgr.NewMemoryStateStore(),
		StoreUp:         func() bool { return world.storeUp },
		StoreReady:      func() bool { return world.storeUp },
		DBInstalled:     func() bool { return true },
		JavaDBInstalled: func() bool { return true },
		TrivyVersion:    func() string { return "0.74.0" },
		WorkersRunning:  func() int { return world.workers },
		QueueStats:      func(ctx context.Context) (queue.Stats, error) { return world.stats, nil },
		RecentScans:     func() queue.Recent { return world.recent },
		OtherDBStates: func(ctx context.Context) ([]store.DBStateDocument, error) {
			return nil, errors.New("not in this test")
		},
	})
}

func getHealth(t *testing.T, h *Handler) (int, healthResponse, string) {
	w := serve(h, request(http.MethodGet, "/api/v2/health", testToken, ""))
	var response healthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response), w.Body.String())
	return w.Code, response, w.Body.String()
}

func checkStatus(response healthResponse, name string) string {
	for _, check := range response.Checks {
		if check.Name == name {
			return check.Status
		}
	}
	return ""
}

func TestHealth(t *testing.T) {
	world := &healthWorld{storeUp: true, workers: 2, stats: queue.Stats{Depth: 3, OldestQueuedAge: time.Minute}}
	h := newHealthHandler(world)
	now := time.Now().UTC()
	fresh := dbmgr.DBState{Mode: dbmgr.ModeNormal, LastConfirmedCurrentAt: now.Add(-time.Hour), Metadata: dbmgr.Metadata{UpdatedAt: now.Add(-time.Hour)}}
	require.NoError(t, h.deps.DBState.Save(context.Background(), "db", fresh))

	code, response, _ := getHealth(t, h)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, healthOK, response.Status)
	assert.Equal(t, &queueView{Depth: 3, OldestQueuedAgeSeconds: 60, Workers: 2}, response.Queue)
	assert.Equal(t, "MongoDB is unavailable", response.InstancesError, "other instances are best effort")
	require.Len(t, response.DBs, 1)

	t.Run("each degraded rule gives 200 degraded, and ok again when it clears", func(t *testing.T) {
		proxied := config.DBSource{Repository: "ghcr.io/aquasecurity/trivy-db:2",
			Proxy: &url.URL{Scheme: "http", User: url.UserPassword("proxyuser", "proxy-secret"), Host: "proxy:3128"}}
		for name, tc := range map[string]struct {
			check string
			set   func()
			reset func()
		}{
			"degraded DB mode": {"db", func() {
				state := fresh
				state.Mode = dbmgr.ModeDegraded
				state.ActiveSource = proxied.String()
				state.LastSources = []dbmgr.SourceResult{{Source: proxied.String(), FailureClass: "tls_timeout"}}
				require.NoError(t, h.deps.DBState.Save(context.Background(), "db", state))
			}, func() { require.NoError(t, h.deps.DBState.Save(context.Background(), "db", fresh)) }},
			"newer DB available": {"db", func() {
				state := fresh
				state.NewerAvailable = true
				require.NoError(t, h.deps.DBState.Save(context.Background(), "db", state))
			}, func() { require.NoError(t, h.deps.DBState.Save(context.Background(), "db", fresh)) }},
			"stale for the default max age": {"db", func() {
				state := fresh
				state.LastConfirmedCurrentAt = now.Add(-7 * time.Hour)
				require.NoError(t, h.deps.DBState.Save(context.Background(), "db", state))
			}, func() { require.NoError(t, h.deps.DBState.Save(context.Background(), "db", fresh)) }},
			"older than SCANNER_DB_AGE_WARN": {"db", func() {
				state := fresh
				state.Metadata.UpdatedAt = now.Add(-8 * 24 * time.Hour)
				require.NoError(t, h.deps.DBState.Save(context.Background(), "db", state))
			}, func() { require.NoError(t, h.deps.DBState.Save(context.Background(), "db", fresh)) }},
			"queue stuck": {"queue", func() { world.stats.OldestQueuedAge = 11 * time.Minute },
				func() { world.stats.OldestQueuedAge = time.Minute }},
			"failure rate": {"recent_scans", func() { world.recent = queue.Recent{Done: 4, Failed: 6} },
				func() { world.recent = queue.Recent{Done: 6, Failed: 4} }},
		} {
			tc.set()
			code, response, body := getHealth(t, h)
			assert.Equal(t, http.StatusOK, code, name)
			assert.Equal(t, healthDegraded, response.Status, name)
			assert.Equal(t, healthDegraded, checkStatus(response, tc.check), name)
			assert.NotContains(t, body, "proxy-secret", name)
			assert.NotContains(t, body, "proxyuser", name)
			tc.reset()
			_, response, _ = getHealth(t, h)
			assert.Equal(t, healthOK, response.Status, "%s cleared", name)
		}
	})

	t.Run("a high failure rate needs ten samples; a stuck queue needs workers", func(t *testing.T) {
		world.recent = queue.Recent{Done: 1, Failed: 8}
		_, response, _ := getHealth(t, h)
		assert.Equal(t, healthOK, checkStatus(response, "recent_scans"))
		world.recent = queue.Recent{}
	})

	t.Run("unhealthy: 503 for a readiness condition or no workers", func(t *testing.T) {
		world.workers = 0
		code, response, _ := getHealth(t, h)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		assert.Equal(t, healthUnhealthy, response.Status)
		assert.Equal(t, healthUnhealthy, checkStatus(response, "workers"))
		world.workers = 2

		world.storeUp = false
		code, response, _ = getHealth(t, h)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		assert.Equal(t, healthUnhealthy, checkStatus(response, "ready"))
		assert.Nil(t, response.Queue, "no queue statistics while MongoDB is down")
		world.storeUp = true

		code, response, _ = getHealth(t, h)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, healthOK, response.Status)
	})

	assert.Equal(t, http.StatusUnauthorized, serve(h, request(http.MethodGet, "/api/v2/health", "", "")).Code)
}
