package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

func TestReadyProbe(t *testing.T) {
	state := map[string]bool{"storeUp": true, "storeReady": true, "db": true, "javaDB": true, "trivy": true}
	cfg := config.Config{AuthToken: testToken, MaxInflight: 4, DBMaxAgeDefault: time.Hour,
		JavaDBSources: []config.DBSource{{Repository: "mirror.local/trivy-java-db:1"}}}
	dbState := dbmgr.NewMemoryStateStore()
	h := NewHandler(cfg, Deps{
		DBState:         dbState,
		StoreUp:         func() bool { return state["storeUp"] },
		StoreReady:      func() bool { return state["storeReady"] },
		DBInstalled:     func() bool { return state["db"] },
		JavaDBInstalled: func() bool { return state["javaDB"] },
		TrivyVersion: func() string {
			if state["trivy"] {
				return "0.74.0"
			}
			return ""
		},
	})
	v1Ready := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	probe := func() int {
		return serve(h.ReadyProbe(v1Ready), request(http.MethodGet, "/probe/ready", "", "")).Code
	}

	require.Equal(t, http.StatusOK, probe(), "ready, without a token")
	require.NoError(t, dbState.Save(context.Background(), "db", dbmgr.DBState{Mode: dbmgr.ModeDegraded, NewerAvailable: true}))
	assert.Equal(t, http.StatusOK, probe(), "a degraded DB mode stays ready")

	for _, condition := range []string{"storeUp", "storeReady", "db", "javaDB", "trivy"} {
		state[condition] = false
		w := serve(h.ReadyProbe(v1Ready), request(http.MethodGet, "/probe/ready", "", ""))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, condition)
		assert.Equal(t, CodeNotReady, errorCode(t, w), condition)
		assert.Len(t, h.NotReady(), 1, condition)
		state[condition] = true
		assert.Equal(t, http.StatusOK, probe(), "ready again when %s clears", condition)
	}

	h.cfg.JavaDBSources = nil
	state["javaDB"] = false
	assert.Equal(t, http.StatusOK, probe(), "no Java sources: no Java DB needed")

	h.StopAccepting()
	assert.Equal(t, http.StatusServiceUnavailable, probe(), "shutting down")
}
