//go:build integration

package apiv2

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func TestGetDB(t *testing.T) {
	e := newEnv(t, nil)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	ctx, cancel := e.client.OperationContext(context.Background())
	defer cancel()
	_, err := e.client.Database().Collection(store.CollectionDBState).InsertMany(ctx, []any{
		store.DBStateDocument{ID: "scanner-2:db", InstanceID: "scanner-2", DB: "db", UpdatedAt: at,
			DBState: dbmgr.DBState{Mode: dbmgr.ModeNormal, LastConfirmedCurrentAt: at, Metadata: dbmgr.Metadata{Version: 2, UpdatedAt: at}}},
		store.DBStateDocument{ID: "scanner-2:java-db", InstanceID: "scanner-2", DB: "java-db", UpdatedAt: at,
			DBState: dbmgr.DBState{Mode: dbmgr.ModeDegraded}},
		store.DBStateDocument{ID: "scanner-1:db", InstanceID: "scanner-1", DB: "db", UpdatedAt: at,
			DBState: dbmgr.DBState{Mode: dbmgr.ModeNormal}},
	})
	require.NoError(t, err)

	w := e.do(http.MethodGet, "/api/v2/db", "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var response struct {
		DBs            []map[string]any `json:"dbs"`
		OtherInstances []struct {
			InstanceID string           `json:"instance_id"`
			DBs        []map[string]any `json:"dbs"`
		} `json:"other_instances"`
		OtherInstancesError string `json:"other_instances_error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Empty(t, response.OtherInstancesError)
	require.Len(t, response.DBs, 1, "this instance, from memory")
	assert.Equal(t, "ok", response.DBs[0]["freshness"])
	require.Len(t, response.OtherInstances, 1, "this instance's own stored document is not repeated")
	assert.Equal(t, "scanner-2", response.OtherInstances[0].InstanceID)
	require.Len(t, response.OtherInstances[0].DBs, 2)
	assert.Equal(t, "db", response.OtherInstances[0].DBs[0]["kind"])
	assert.Equal(t, "ok", response.OtherInstances[0].DBs[0]["freshness"])
	assert.Contains(t, response.OtherInstances[0].DBs[0], "state_updated_at")
	assert.Equal(t, "degraded", response.OtherInstances[0].DBs[1]["mode"])
}
