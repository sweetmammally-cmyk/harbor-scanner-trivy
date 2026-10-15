package dbmgr

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadMetadata(t *testing.T) {
	writeMetadata := func(t *testing.T, content string) string {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(content), 0o644))
		return dir
	}

	t.Run("real Trivy metadata", func(t *testing.T) {
		dir := writeMetadata(t, `{"Version":2,"NextUpdate":"2026-09-28T07:04:17.756799482Z","UpdatedAt":"2026-09-27T07:04:17.756799612Z","DownloadedAt":"2026-09-27T07:44:09.999745202Z"}`)

		metadata, err := readMetadata(dir)

		require.NoError(t, err)
		assert.Equal(t, 2, metadata.Version)
		assert.Equal(t, time.Date(2026, 9, 27, 7, 4, 17, 756799612, time.UTC), metadata.UpdatedAt.UTC())
		assert.Equal(t, time.Date(2026, 9, 28, 7, 4, 17, 756799482, time.UTC), metadata.NextUpdate.UTC())
		assert.Equal(t, time.Date(2026, 9, 27, 7, 44, 9, 999745202, time.UTC), metadata.DownloadedAt.UTC())
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := readMetadata(t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading DB metadata")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := readMetadata(writeMetadata(t, `{"Version":`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding DB metadata")
	})

	t.Run("no UpdatedAt", func(t *testing.T) {
		_, err := readMetadata(writeMetadata(t, `{"Version":2}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no UpdatedAt")
	})
}
