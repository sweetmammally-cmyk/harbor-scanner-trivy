//go:build integration

package apiv2

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestDBBlock(t *testing.T) {
	t.Run("GET returns the stored db block; a hit recomputes freshness for its own max_db_age", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		done := e.finish(t, smallFindings[:1])
		setFields(t, e, done.ID, bson.M{"$set": bson.M{"db.freshness": "stale"}})

		w := e.do(http.MethodGet, "/api/v2/scans/"+done.ID, "")
		require.Equal(t, http.StatusOK, w.Code)
		db := decode(t, w)["db"].(map[string]any)
		assert.Equal(t, "stale", db["freshness"], "the stored value, although the local DB is fresh")
		assert.Equal(t, done.DB.UpdatedAt.Format(time.RFC3339Nano), db["updated_at"])
		assert.Equal(t, done.ConfirmedAt.UTC().Format(time.RFC3339Nano), db["confirmed_at"])

		// The local DB was confirmed current an hour ago (newEnv).
		w = e.post(body("v1", `"npm"`, `"max_db_age":"30m"`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "stale", decode(t, w)["db"].(map[string]any)["freshness"])
		assert.Equal(t, "stale", e.scan(t, done.ID).DB.Freshness)

		w = e.post(body("v1", `"npm"`, `"max_db_age":"3h"`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "ok", decode(t, w)["db"].(map[string]any)["freshness"])
		assert.Equal(t, "ok", e.scan(t, done.ID).DB.Freshness, "stored with the renewal")
	})

	t.Run("a tag without a result shows the local DB state", func(t *testing.T) {
		e := newEnv(t, nil)
		local, err := e.dbState.Get(context.Background(), "db")
		require.NoError(t, err)

		w := e.post(body("v1", `"npm"`, `"max_db_age":"30m"`))

		require.Equal(t, http.StatusAccepted, w.Code)
		db := decode(t, w)["db"].(map[string]any)
		assert.Equal(t, "stale", db["freshness"])
		assert.Equal(t, local.Metadata.UpdatedAt.Format(time.RFC3339Nano), db["updated_at"])
		assert.NotContains(t, db, "confirmed_at")
	})
}
