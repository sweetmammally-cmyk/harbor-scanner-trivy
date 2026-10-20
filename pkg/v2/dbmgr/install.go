package dbmgr

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// ErrNoDB is returned by PinActiveVersion when the DB is not installed.
var ErrNoDB = errors.New("DB is not installed")

// pinned counts the scans using each version directory (cache-dir relative path
// joined to the cache dir). InstallDB never removes a pinned version. pinMu also
// covers the symlink swap and the cleanup, so a version cannot be removed between
// being resolved and being pinned.
var (
	pinMu  sync.Mutex
	pinned = map[string]int{}
)

// PinActiveVersion returns the active version directory of a DB ("db" or
// "java-db") and pins it until unpin is called, so a scan keeps its DB even when
// newer versions are installed meanwhile. It returns ErrNoDB when no DB is installed.
func PinActiveVersion(cacheDir, dbName string) (dir string, unpin func(), err error) {
	dbFile := trivyDB.Files[0]
	if dbName == javaDB.Name {
		dbFile = javaDB.Files[0]
	}

	pinMu.Lock()
	defer pinMu.Unlock()
	target, err := os.Readlink(filepath.Join(cacheDir, dbName))
	if err != nil {
		return "", nil, ErrNoDB
	}
	dir = filepath.Join(cacheDir, target)
	if info, err := os.Stat(filepath.Join(dir, dbFile)); err != nil || !info.Mode().IsRegular() {
		return "", nil, ErrNoDB
	}
	pinned[dir]++
	return dir, func() {
		pinMu.Lock()
		defer pinMu.Unlock()
		pinned[dir]--
		if pinned[dir] == 0 {
			delete(pinned, dir)
		}
	}, nil
}

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

// InstallDB makes versionDir (from newVersionDir, with the DB files in it) the
// active DB, then removes versions older than the previous one.
func InstallDB(cacheDir, dbName, versionDir, manifestDigest string) error {
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

	// The swap and the cleanup run under pinMu, see PinActiveVersion.
	pinMu.Lock()
	defer pinMu.Unlock()

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

	// Keep the new and the previous version and every version a scan has pinned;
	// remove the rest, including directories left by failed downloads.
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return fmt.Errorf("cleaning %s: %w", versionsDir, err)
	}
	for _, entry := range entries {
		if entry.Name() == filepath.Base(versionDir) || entry.Name() == filepath.Base(previous) {
			continue
		}
		if pinned[filepath.Join(versionsDir, entry.Name())] > 0 {
			continue
		}
		if err = os.RemoveAll(filepath.Join(versionsDir, entry.Name())); err != nil {
			return fmt.Errorf("removing old DB version %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// InstalledDigest returns the manifest digest of the active DB, or "" when there
// is no DB or it has no recorded digest (for example the seed DB).
func InstalledDigest(cacheDir, dbName string) string {
	data, err := os.ReadFile(filepath.Join(cacheDir, dbName, manifestDigestFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// dbPresent reports whether an active DB exists: <cacheDir>/<dbName>/<dbFile>
// is a regular file. The service is not ready until it is true (DEMAND section 7.1).
func dbPresent(cacheDir, dbName, dbFile string) bool {
	info, err := os.Stat(filepath.Join(cacheDir, dbName, dbFile))
	return err == nil && info.Mode().IsRegular()
}

// installSeed installs the seed DB from seedDir when no DB is active yet.
// files are the DB files to copy; the first one is the DB file itself.
// The seed gets no manifest digest, so the first upstream check always downloads.
// It returns false without error when a DB is already active or there is no seed.
func installSeed(cacheDir, dbName, seedDir string, files []string) (bool, error) {
	if dbPresent(cacheDir, dbName, files[0]) {
		return false, nil
	}
	if _, err := os.Stat(seedDir); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	versionDir, err := newVersionDir(cacheDir, dbName)
	if err != nil {
		return false, err
	}
	for _, name := range files {
		if err = copyFile(filepath.Join(seedDir, name), filepath.Join(versionDir, name)); err != nil {
			_ = os.RemoveAll(versionDir)
			return false, fmt.Errorf("copying seed DB: %w", err)
		}
	}
	if err = InstallDB(cacheDir, dbName, versionDir, ""); err != nil {
		return false, err
	}
	return true, nil
}

func copyFile(from, to string) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	target, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(target, source)
	if err == nil {
		err = target.Sync()
	}
	closeErr := target.Close()
	if err != nil {
		return err
	}
	return closeErr
}
