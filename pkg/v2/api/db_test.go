package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

func TestGetDB_WhileMongoIsDown(t *testing.T) {
	h := newTestHandler(&fakeResolver{}, readiness{})
	h.cfg.InstanceID = "scanner-1"
	h.cfg.JavaDBSources = []config.DBSource{{Repository: "mirror.local/trivy-java-db:1"}}
	proxied := config.DBSource{Repository: "ghcr.io/aquasecurity/trivy-db:2",
		Proxy: &url.URL{Scheme: "http", User: url.UserPassword("proxyuser", "proxy-secret"), Host: "proxy:3128"}}
	updated := time.Now().Add(-5 * time.Hour).UTC()
	require.NoError(t, h.deps.DBState.Save(context.Background(), "db", dbmgr.DBState{
		Mode: dbmgr.ModeDegraded, ActiveSource: proxied.String(), NewerAvailable: true,
		Metadata:    dbmgr.Metadata{Version: 2, UpdatedAt: updated},
		LastSources: []dbmgr.SourceResult{{Source: proxied.String(), FailureClass: "tcp_timeout"}},
	}))

	w := serve(h, request(http.MethodGet, "/api/v2/db", testToken, ""))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "proxy-secret")
	assert.NotContains(t, w.Body.String(), "proxyuser")
	var response dbResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "scanner-1", response.InstanceID)
	assert.Equal(t, "MongoDB is unavailable", response.OtherInstancesError)
	require.Len(t, response.DBs, 2, "db and java-db")
	db := response.DBs[0]
	assert.Equal(t, "db", db.Kind)
	assert.Equal(t, dbmgr.ModeDegraded, db.Mode)
	assert.True(t, db.NewerAvailable)
	assert.Equal(t, dbmgr.FreshnessStale, db.Freshness, "stale while a newer DB is available")
	assert.InDelta(t, 5*3600, db.DBAgeSeconds, 5)
	assert.Equal(t, "tcp_timeout", db.LastSources[0].FailureClass)
	assert.Equal(t, "java-db", response.DBs[1].Kind)
	assert.Empty(t, response.DBs[1].LastSources, "no state yet: an empty list")

	assert.Equal(t, http.StatusUnauthorized, serve(h, request(http.MethodGet, "/api/v2/db", "", "")).Code)
}
