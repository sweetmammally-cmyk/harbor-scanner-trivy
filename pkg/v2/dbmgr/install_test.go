package dbmgr

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// downloadedVersion creates a version directory with a trivy.db holding content.
func downloadedVersion(t *testing.T, cacheDir, content string) string {
	t.Helper()
	dir, err := newVersionDir(cacheDir, "db")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy.db"), []byte(content), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), []byte("{}"), 0o644))
	return dir
}

func readDB(t *testing.T, cacheDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cacheDir, "db", "trivy.db"))
	require.NoError(t, err)
	return string(data)
}

func versionNames(t *testing.T, cacheDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(cacheDir, "db-versions"))
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestInstallDB(t *testing.T) {
	t.Run("first install creates the symlink", func(t *testing.T) {
		cacheDir := t.TempDir()
		v1 := downloadedVersion(t, cacheDir, "db v1")

		require.NoError(t, installDB(cacheDir, "db", v1, "sha256:v1"))

		target, err := os.Readlink(filepath.Join(cacheDir, "db"))
		require.NoError(t, err)
		assert.Equal(t, filepath.Join("db-versions", filepath.Base(v1)), target, "the symlink is relative")
		assert.Equal(t, "db v1", readDB(t, cacheDir))
		assert.Equal(t, "sha256:v1", InstalledDigest(cacheDir, "db"))
	})

	t.Run("updates keep the current and the previous version only", func(t *testing.T) {
		cacheDir := t.TempDir()
		v1 := downloadedVersion(t, cacheDir, "db v1")
		require.NoError(t, installDB(cacheDir, "db", v1, "sha256:v1"))
		v2 := downloadedVersion(t, cacheDir, "db v2")
		require.NoError(t, installDB(cacheDir, "db", v2, "sha256:v2"))

		assert.Equal(t, "db v2", readDB(t, cacheDir))
		assert.ElementsMatch(t, []string{filepath.Base(v1), filepath.Base(v2)}, versionNames(t, cacheDir))

		failed := downloadedVersion(t, cacheDir, "left by a failed download")
		v3 := downloadedVersion(t, cacheDir, "db v3")
		require.NoError(t, installDB(cacheDir, "db", v3, "sha256:v3"))

		assert.Equal(t, "db v3", readDB(t, cacheDir))
		assert.Equal(t, "sha256:v3", InstalledDigest(cacheDir, "db"))
		assert.ElementsMatch(t, []string{filepath.Base(v2), filepath.Base(v3)}, versionNames(t, cacheDir))
		assert.NoDirExists(t, failed)
		assert.NoFileExists(t, filepath.Join(cacheDir, "db.new"))
	})

	t.Run("a scan that opened the DB before the swap keeps reading its copy", func(t *testing.T) {
		cacheDir := t.TempDir()
		v1 := downloadedVersion(t, cacheDir, "db v1")
		require.NoError(t, installDB(cacheDir, "db", v1, "sha256:v1"))

		inFlight, err := os.Open(filepath.Join(cacheDir, "db", "trivy.db"))
		require.NoError(t, err)
		defer inFlight.Close()

		// Two swaps: the first keeps v1 as previous, the second deletes it.
		require.NoError(t, installDB(cacheDir, "db", downloadedVersion(t, cacheDir, "db v2"), "sha256:v2"))
		require.NoError(t, installDB(cacheDir, "db", downloadedVersion(t, cacheDir, "db v3"), "sha256:v3"))

		data, err := io.ReadAll(inFlight)
		require.NoError(t, err)
		assert.Equal(t, "db v1", string(data))
		assert.Equal(t, "db v3", readDB(t, cacheDir))
	})

	t.Run("a real db directory from an older layout becomes the previous version", func(t *testing.T) {
		cacheDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "db"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "db", "trivy.db"), []byte("seed db"), 0o644))
		assert.Equal(t, "", InstalledDigest(cacheDir, "db"), "a seed DB has no recorded digest")

		v1 := downloadedVersion(t, cacheDir, "db v1")
		require.NoError(t, installDB(cacheDir, "db", v1, "sha256:v1"))

		assert.Equal(t, "db v1", readDB(t, cacheDir))
		names := versionNames(t, cacheDir)
		require.Len(t, names, 2)
		for _, name := range names {
			if name != filepath.Base(v1) {
				seed, err := os.ReadFile(filepath.Join(cacheDir, "db-versions", name, "trivy.db"))
				require.NoError(t, err)
				assert.Equal(t, "seed db", string(seed))
			}
		}
	})

	t.Run("java-db uses its own link and versions", func(t *testing.T) {
		cacheDir := t.TempDir()
		dir, err := newVersionDir(cacheDir, "java-db")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "trivy-java.db"), []byte("java"), 0o644))

		require.NoError(t, installDB(cacheDir, "java-db", dir, "sha256:java"))

		data, err := os.ReadFile(filepath.Join(cacheDir, "java-db", "trivy-java.db"))
		require.NoError(t, err)
		assert.Equal(t, "java", string(data))
		assert.Equal(t, "sha256:java", InstalledDigest(cacheDir, "java-db"))
		assert.Equal(t, "", InstalledDigest(cacheDir, "db"))
	})
}

func TestInstallSeed(t *testing.T) {
	writeSeed := func(t *testing.T, files ...string) string {
		seedDir := t.TempDir()
		for i := 0; i < len(files); i += 2 {
			require.NoError(t, os.WriteFile(filepath.Join(seedDir, files[i]), []byte(files[i+1]), 0o644))
		}
		return seedDir
	}

	t.Run("installs the seed when there is no DB", func(t *testing.T) {
		cacheDir := t.TempDir()
		seedDir := writeSeed(t, "trivy.db", "seed db", "metadata.json", "{}")
		assert.False(t, dbPresent(cacheDir, "db", "trivy.db"), "not ready before the seed")

		installed, err := installSeed(cacheDir, "db", seedDir, dbFiles)

		require.NoError(t, err)
		assert.True(t, installed)
		assert.True(t, dbPresent(cacheDir, "db", "trivy.db"))
		assert.Equal(t, "seed db", readDB(t, cacheDir))
		assert.Equal(t, "", InstalledDigest(cacheDir, "db"), "the first upstream check must download")
	})

	t.Run("keeps an installed DB", func(t *testing.T) {
		cacheDir := t.TempDir()
		require.NoError(t, installDB(cacheDir, "db", downloadedVersion(t, cacheDir, "db v1"), "sha256:v1"))
		seedDir := writeSeed(t, "trivy.db", "seed db", "metadata.json", "{}")

		installed, err := installSeed(cacheDir, "db", seedDir, dbFiles)

		require.NoError(t, err)
		assert.False(t, installed)
		assert.Equal(t, "db v1", readDB(t, cacheDir))
	})

	t.Run("no seed directory means no seed and not ready", func(t *testing.T) {
		cacheDir := t.TempDir()

		installed, err := installSeed(cacheDir, "db", filepath.Join(t.TempDir(), "missing"), dbFiles)

		require.NoError(t, err)
		assert.False(t, installed)
		assert.False(t, dbPresent(cacheDir, "db", "trivy.db"))
	})

	t.Run("incomplete seed is an error and leaves nothing behind", func(t *testing.T) {
		cacheDir := t.TempDir()
		seedDir := writeSeed(t, "trivy.db", "seed db")

		installed, err := installSeed(cacheDir, "db", seedDir, dbFiles)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "copying seed DB")
		assert.False(t, installed)
		assert.False(t, dbPresent(cacheDir, "db", "trivy.db"))
		assert.Empty(t, versionNames(t, cacheDir))
	})

	t.Run("a directory named like the DB file is not a DB", func(t *testing.T) {
		cacheDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "db", "trivy.db"), 0o755))

		assert.False(t, dbPresent(cacheDir, "db", "trivy.db"))
	})
}
