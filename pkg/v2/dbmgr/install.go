package dbmgr

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DB directory layout (DEMAND section 7.1), for dbName "db" (and "java-db"):
//
//	<cacheDir>/db               symlink to db-versions/<version>, the path Trivy reads
//	<cacheDir>/db-versions/...  one directory per downloaded DB
//
// A new DB is downloaded into its own version directory and then made active by
// replacing the symlink with a rename, which is atomic: a scan sees either the
// old or the new DB, never a half-written one. The previous version is kept so
// scans that started before the swap keep their copy.

// manifestDigestFile is written next to the DB files and holds the manifest
// digest of the installed DB, for the upstream check after a restart.
const manifestDigestFile = "manifest-digest"

// newVersionDir creates an empty directory to download a new DB version into.
func newVersionDir(cacheDir, dbName string) (string, error) {
	versionsDir := filepath.Join(cacheDir, dbName+"-versions")
	if err := os.MkdirAll(versionsDir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", versionsDir, err)
	}
	dir, err := os.MkdirTemp(versionsDir, "v-")
	if err != nil {
		return "", fmt.Errorf("creating version directory in %s: %w", versionsDir, err)
	}
	return dir, nil
}

// installDB makes versionDir (from newVersionDir, with the DB files in it) the
// active DB, then removes versions older than the previous one.
func installDB(cacheDir, dbName, versionDir, manifestDigest string) error {
	if err := os.WriteFile(filepath.Join(versionDir, manifestDigestFile), []byte(manifestDigest), 0o644); err != nil {
		return fmt.Errorf("writing manifest digest: %w", err)
	}

	link := filepath.Join(cacheDir, dbName)
	versionsDir := filepath.Join(cacheDir, dbName+"-versions")

	// An older layout or a seed DB can leave a real directory where the symlink goes.
	// Move it into the versions directory once, so it becomes the previous version.
	info, err := os.Lstat(link)
	if err == nil && info.IsDir() {
		moved, err := os.MkdirTemp(versionsDir, "v-")
		if err != nil {
			return fmt.Errorf("moving old DB directory: %w", err)
		}
		if err = os.Remove(moved); err != nil {
			return fmt.Errorf("moving old DB directory: %w", err)
		}
		if err = os.Rename(link, moved); err != nil {
			return fmt.Errorf("moving old DB directory: %w", err)
		}
		if err = os.Symlink(filepath.Join(dbName+"-versions", filepath.Base(moved)), link); err != nil {
			return fmt.Errorf("linking old DB directory: %w", err)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking %s: %w", link, err)
	}

	previous, _ := os.Readlink(link)

	// Write the new symlink next to the old one, then rename it over the old one.
	newLink := link + ".new"
	_ = os.Remove(newLink)
	if err = os.Symlink(filepath.Join(dbName+"-versions", filepath.Base(versionDir)), newLink); err != nil {
		return fmt.Errorf("creating symlink: %w", err)
	}
	if err = os.Rename(newLink, link); err != nil {
		return fmt.Errorf("activating DB version: %w", err)
	}

	// Keep the new and the previous version; remove the rest, including
	// directories left by failed downloads.
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return fmt.Errorf("cleaning %s: %w", versionsDir, err)
	}
	for _, entry := range entries {
		if entry.Name() == filepath.Base(versionDir) || entry.Name() == filepath.Base(previous) {
			continue
		}
		if err = os.RemoveAll(filepath.Join(versionsDir, entry.Name())); err != nil {
			return fmt.Errorf("removing old DB version %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// installedDigest returns the manifest digest of the active DB, or "" when there
// is no DB or it has no recorded digest (for example the seed DB).
func installedDigest(cacheDir, dbName string) string {
	data, err := os.ReadFile(filepath.Join(cacheDir, dbName, manifestDigestFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
