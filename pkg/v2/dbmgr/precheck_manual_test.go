//go:build manual

package dbmgr

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// TestManualUpdate runs a full update (pre-check, upstream check, download, install)
// against real sources into SCANNER_TRIVY_CACHE_DIR (a temporary directory when unset):
//
//	SCANNER_DB_SOURCES='ghcr.io/aquasecurity/trivy-db:2|direct' SCANNER_TRIVY_CACHE_DIR=/tmp/trivy-cache \
//	  go test -tags=manual -count=1 -v -timeout 30m -run TestManualUpdate ./pkg/v2/dbmgr/
//
// With SCANNER_JAVA_DB_SOURCES set it then updates the Java DB as well.
func TestManualUpdate(t *testing.T) {
	cfg, err := config.GetConfig()
	require.NoError(t, err)
	if len(cfg.DBSources) == 0 {
		t.Skip("set SCANNER_DB_SOURCES to the source(s) to update from")
	}
	cacheDir := os.Getenv("SCANNER_TRIVY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = t.TempDir()
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	start := time.Now()
	result := update(context.Background(), cfg, cacheDir, trivyDB, cfg.DBSources)
	duration := time.Since(start)

	result.Sources = nil // the pre-check details are already in the log
	printed, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)
	t.Logf("update took %s\n%s", duration.Round(time.Millisecond), printed)
	for _, name := range trivyDB.Files {
		if info, err := os.Stat(filepath.Join(cacheDir, trivyDB.Name, name)); err == nil {
			t.Logf("%s: %d bytes", name, info.Size())
		}
	}

	// The Java DB too, when SCANNER_JAVA_DB_SOURCES is set.
	if len(cfg.JavaDBSources) == 0 {
		return
	}
	start = time.Now()
	result = update(context.Background(), cfg, cacheDir, javaDB, cfg.JavaDBSources)
	result.Sources = nil
	printed, err = json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)
	t.Logf("Java DB update took %s\n%s", time.Since(start).Round(time.Millisecond), printed)
	for _, name := range javaDB.Files {
		if info, err := os.Stat(filepath.Join(cacheDir, javaDB.Name, name)); err == nil {
			t.Logf("%s: %d bytes", name, info.Size())
		}
	}
}
