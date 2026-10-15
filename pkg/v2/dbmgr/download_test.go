package dbmgr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckUpstream(t *testing.T) {
	f := startFakeOCIRegistry(t, []byte("db layer"))
	client, err := newRegistryClient(f.source(t, "direct"))
	require.NoError(t, err)

	t.Run("same digest is unchanged", func(t *testing.T) {
		manifest, digest, changed, err := checkUpstream(testContext(t), client, f.manifestDigest)

		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, f.manifestDigest, digest)
		assert.Equal(t, f.layerDigest, manifest.Layers[0].Digest)
	})

	t.Run("different digest is changed", func(t *testing.T) {
		old := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		_, digest, changed, err := checkUpstream(testContext(t), client, old)

		require.NoError(t, err)
		assert.True(t, changed)
		assert.Equal(t, f.manifestDigest, digest)
	})

	t.Run("no installed digest is changed", func(t *testing.T) {
		_, _, changed, err := checkUpstream(testContext(t), client, "")

		require.NoError(t, err)
		assert.True(t, changed)
	})

	t.Run("registry error", func(t *testing.T) {
		source := f.source(t, "direct")
		source.Repository = strings.Replace(source.Repository, ":2", ":9", 1)
		missing, err := newRegistryClient(source)
		require.NoError(t, err)

		_, _, changed, err := checkUpstream(testContext(t), missing, f.manifestDigest)

		assert.EqualError(t, err, "upstream check: GET manifest aquasec/trivy-db:9 returned status 404")
		assert.False(t, changed)
	})
}
