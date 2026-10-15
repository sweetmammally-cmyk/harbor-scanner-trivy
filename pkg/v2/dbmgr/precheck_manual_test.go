//go:build manual

package dbmgr

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// TestManualPrecheck runs the pre-check against real sources, for debugging a mirror or proxy.
// It reads the normal v2 settings from env (SCANNER_DB_SOURCES and SCANNER_PRECHECK_TIMEOUT_*):
//
//	SCANNER_DB_SOURCES='ghcr.io/aquasecurity/trivy-db:2|direct' \
//	  go test -tags=manual -count=1 -v -run TestManualPrecheck ./pkg/v2/dbmgr/
func TestManualPrecheck(t *testing.T) {
	cfg, err := config.GetConfig()
	require.NoError(t, err)
	if len(cfg.DBSources) == 0 {
		t.Skip("set SCANNER_DB_SOURCES to the source(s) to check")
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	for _, source := range cfg.DBSources {
		result := Precheck(context.Background(), source, cfg)
		printed, err := json.MarshalIndent(result, "", "  ")
		require.NoError(t, err)
		t.Logf("%s", printed)
	}
}
