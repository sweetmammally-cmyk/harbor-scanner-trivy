//go:build manual

package runner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// TestManualScan resolves a real image and scans it with the real Trivy, using a
// DB installed in our layout (run TestManualUpdate in pkg/v2/dbmgr first):
//
//	SCANNER_TRIVY_CACHE_DIR=<dir with db installed> MANUAL_IMAGE=library/node:22-alpine3.20 \
//	  [MANUAL_REGISTRY_URL=https://registry-1.docker.io] [MANUAL_PLATFORMS=alpine,node-pkg] \
//	  go test -tags=manual -count=1 -v -timeout 30m -run TestManualScan ./pkg/v2/runner/
func TestManualScan(t *testing.T) {
	cacheDir := os.Getenv("SCANNER_TRIVY_CACHE_DIR")
	imageName := os.Getenv("MANUAL_IMAGE")
	if cacheDir == "" || imageName == "" {
		t.Skip("set SCANNER_TRIVY_CACHE_DIR and MANUAL_IMAGE")
	}
	registryURL := os.Getenv("MANUAL_REGISTRY_URL")
	if registryURL == "" {
		registryURL = "https://registry-1.docker.io"
	}
	platforms := []string{"alpine", "node-pkg", "jar"}
	if value := os.Getenv("MANUAL_PLATFORMS"); value != "" {
		platforms = strings.Split(value, ",")
	}
	path, tag, _ := strings.Cut(imageName, ":")
	repository, name, _ := strings.Cut(path, "/")

	cfg := config.Config{RegistryURL: registryURL, RegistryTimeout: 30 * time.Second,
		ScanTimeout: 15 * time.Minute, ScanMaxOutput: 256 << 20, ScanMaxFindings: 10000, ScanPlatform: "linux/amd64"}
	client, err := registry.NewClient(cfg)
	require.NoError(t, err)
	resolved, err := client.Resolve(context.Background(), registry.Image{Repository: repository, Name: name, Tag: tag})
	require.NoError(t, err)
	t.Logf("resolved %s to %s (%s)", imageName, resolved.Reference, resolved.MediaType)

	trivy, err := exec.LookPath("trivy")
	require.NoError(t, err)
	r := NewRunner(cfg, trivy, cacheDir, t.TempDir(), store.NewMemoryPlatforms())
	require.NoError(t, r.CheckTrivy(context.Background()))

	scan := store.Scan{ID: "manual", Image: store.Image{Repository: repository, Name: name, Tag: tag, Digest: resolved.Digest},
		Options: store.ScanOptions{Platforms: platforms, Severity: []string{"HIGH", "CRITICAL"}}}
	start := time.Now()
	scan, report, err := r.Scan(context.Background(), "manual", scan, resolved.Reference)
	if err != nil {
		t.Logf("scan failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
		return
	}
	t.Logf("scan took %s; trivy %s, DB updated %s (%s)", time.Since(start).Round(time.Millisecond),
		scan.Trivy.Version, scan.Trivy.DBUpdatedAt, scan.Trivy.DBManifestDigest)
	t.Logf("image platforms %v; found %v; not found %v; has more %v",
		scan.Platforms, scan.PlatformsFound, scan.PlatformsNotFound, scan.HasMorePlatforms)
	t.Logf("summary %v; findings stored %d; truncated %v", scan.Summary, len(report["findings"].([]Finding)), scan.Truncated)
}
