package dbmgr

import (
	"context"
	"fmt"
)

// checkUpstream is the cheap upstream check of DEMAND section 7.2: it gets the
// remote manifest and compares its digest with installedDigest, the manifest
// digest of the DB we have. An empty installedDigest (for example the seed DB)
// always counts as changed. It returns the manifest so a download can follow
// without asking again.
func checkUpstream(ctx context.Context, client *registryClient, installedDigest string) (ociManifest, string, bool, error) {
	manifest, digest, err := client.getManifest(ctx)
	if err != nil {
		return ociManifest{}, "", false, fmt.Errorf("upstream check: %w", err)
	}
	return manifest, digest, digest != installedDigest, nil
}
