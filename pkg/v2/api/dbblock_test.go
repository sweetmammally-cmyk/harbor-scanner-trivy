package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func TestDBBlock(t *testing.T) {
	h := newTestHandler(&fakeResolver{}, readiness{})
	checked := time.Now().Add(-2 * time.Hour).UTC()
	local := dbmgr.DBState{Mode: dbmgr.ModeNormal, LastUpstreamCheckAt: checked, LastConfirmedCurrentAt: checked,
		Metadata: dbmgr.Metadata{UpdatedAt: checked.Add(-time.Hour)}}
	require.NoError(t, h.deps.DBState.Save(context.Background(), "db", local))

	t.Run("a result: the stored values, never recomputed; the upstream check is this instance's", func(t *testing.T) {
		updated := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		confirmed := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
		scan := store.Scan{Result: &store.ScanResult{}, DB: &store.ScanDB{UpdatedAt: updated, Freshness: "stale"}, ConfirmedAt: &confirmed}

		block := h.dbBlock(context.Background(), scan)

		assert.Equal(t, dbBlock{UpdatedAt: &updated, LastUpstreamCheckAt: &checked, ConfirmedAt: &confirmed, Freshness: "stale"}, block)
	})

	t.Run("no result yet: the local DB state, freshness against the request's max_db_age", func(t *testing.T) {
		ok := h.dbBlock(context.Background(), store.Scan{Options: store.ScanOptions{MaxDBAge: 3 * time.Hour}})
		assert.Equal(t, "ok", ok.Freshness)
		assert.Equal(t, local.Metadata.UpdatedAt, *ok.UpdatedAt)
		assert.Nil(t, ok.ConfirmedAt)

		stale := h.dbBlock(context.Background(), store.Scan{Options: store.ScanOptions{MaxDBAge: time.Hour}})
		assert.Equal(t, "stale", stale.Freshness, "confirmed 2h ago, max_db_age 1h")

		defaultAge := h.dbBlock(context.Background(), store.Scan{})
		assert.Equal(t, "ok", defaultAge.Freshness, "the default max age (6h)")
	})
}
