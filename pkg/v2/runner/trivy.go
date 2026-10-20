// Package runner runs Trivy for a scan and turns its output into the stored
// result (DEMAND section 6.2).
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// Failure classes of a scan.
const (
	FailureTimeout        = "trivy_timeout"
	FailureExit           = "trivy_exit_error"
	FailureOutputTooLarge = "output_too_large"
	FailureOutputInvalid  = "output_invalid"
	FailureDBMissing      = "db_missing"
	FailureJavaDBMissing  = "java_db_missing"
	// FailurePlatformNotFound: the image index has no manifest for SCANNER_SCAN_PLATFORM.
	FailurePlatformNotFound = "platform_not_found"
)

// stderrTail is how much of Trivy's stderr is kept for a failed scan.
const stderrTail = 8 << 10

// ScanError is a failed scan. Detail never contains credentials.
type ScanError struct {
	Class  string
	Detail string
}

func (e *ScanError) Error() string {
	return e.Class + ": " + e.Detail
}

// DBInfo is the DB version a scan used.
type DBInfo struct {
	UpdatedAt      time.Time
	ManifestDigest string
}

// Runner runs Trivy. Each worker has its own Trivy cache directory below workDir;
// the DBs are read from the updater's cacheDir.
type Runner struct {
	cfg      config.Config
	trivy    string
	cacheDir string
	workDir  string
	// tmpDir holds one temporary directory per running scan.
	tmpDir string
	// dirSize measures a directory; tests replace it.
	dirSize   func(path string) (int64, error)
	plainHTTP bool
	platforms store.PlatformRepository

	// version is Trivy's version from CheckTrivy; empty while Trivy is missing.
	mu      sync.Mutex
	version string
}

// NewRunner returns a runner for the Trivy binary at trivyPath that records the
// platforms it finds in platforms. Call CheckTrivy before scanning.
func NewRunner(cfg config.Config, trivyPath, cacheDir, workDir, tmpDir string, platforms store.PlatformRepository) *Runner {
	return &Runner{
		cfg:       cfg,
		trivy:     trivyPath,
		cacheDir:  cacheDir,
		workDir:   workDir,
		tmpDir:    tmpDir,
		dirSize:   dirSize,
		plainHTTP: strings.HasPrefix(cfg.RegistryURL, "http://"),
		platforms: platforms,
	}
}

// runTrivy scans reference (host/repository/name@digest) with the worker's cache
// directory and returns the path of Trivy's JSON output, which the caller must
// remove, and the DB version used. The DB versions stay pinned during the run.
// It logs "triggering scan" with logger once the DB version is known.
func (r *Runner) runTrivy(ctx context.Context, logger *slog.Logger, worker, reference string) (string, DBInfo, error) {
	cacheDir := filepath.Join(r.workDir, worker)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", DBInfo{}, fmt.Errorf("creating the worker cache directory: %w", err)
	}

	// Point the worker's cache at the concrete DB versions and pin them.
	dbDir, unpin, err := dbmgr.PinActiveVersion(r.cacheDir, "db")
	if err != nil {
		return "", DBInfo{}, &ScanError{Class: FailureDBMissing, Detail: "no vulnerability DB is installed"}
	}
	defer unpin()
	if err = replaceSymlink(dbDir, filepath.Join(cacheDir, "db")); err != nil {
		return "", DBInfo{}, err
	}
	javaDir, unpinJava, err := dbmgr.PinActiveVersion(r.cacheDir, "java-db")
	if err == nil {
		defer unpinJava()
		err = replaceSymlink(javaDir, filepath.Join(cacheDir, "java-db"))
	} else {
		// No Java DB: Trivy fails on images with jars, which is java_db_missing.
		err = os.Remove(filepath.Join(cacheDir, "java-db"))
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		return "", DBInfo{}, fmt.Errorf("linking the Java DB: %w", err)
	}

	metadata, err := dbmgr.ReadMetadata(dbDir)
	if err != nil {
		return "", DBInfo{}, &ScanError{Class: FailureDBMissing, Detail: err.Error()}
	}
	db := DBInfo{UpdatedAt: metadata.UpdatedAt, ManifestDigest: dbmgr.InstalledDigest(cacheDir, "db")}
	logger.Info("triggering scan", slog.Time("db_updated_at", db.UpdatedAt), slog.String("db_manifest_digest", db.ManifestDigest))

	// The scan's own temporary directory: Trivy's TMPDIR and the output file.
	// The caller removes it with the output; on failure it is removed here.
	if err = os.MkdirAll(r.tmpDir, 0o700); err != nil {
		return "", DBInfo{}, fmt.Errorf("creating the temp directory: %w", err)
	}
	scanTmp, err := os.MkdirTemp(r.tmpDir, "scan-")
	if err != nil {
		return "", DBInfo{}, fmt.Errorf("creating the scan's temp directory: %w", err)
	}
	outputPath := filepath.Join(scanTmp, "output.json")
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.RemoveAll(scanTmp)
		return "", DBInfo{}, fmt.Errorf("creating the output file: %w", err)
	}
	_ = output.Close()

	scanErr := r.exec(ctx, cacheDir, scanTmp, outputPath, reference)
	if scanErr == nil {
		var info os.FileInfo
		info, err = os.Stat(outputPath)
		switch {
		case err != nil:
			scanErr = &ScanError{Class: FailureOutputInvalid, Detail: "no output file: " + err.Error()}
		case info.Size() > r.cfg.ScanMaxOutput:
			scanErr = &ScanError{Class: FailureOutputTooLarge,
				Detail: fmt.Sprintf("Trivy wrote %d bytes, more than SCANNER_SCAN_MAX_OUTPUT (%d)", info.Size(), r.cfg.ScanMaxOutput)}
		}
	}
	if scanErr != nil {
		_ = os.RemoveAll(scanTmp)
		return "", DBInfo{}, scanErr
	}
	return outputPath, db, nil
}

// exec runs Trivy once. Trivy gets a --timeout slightly below
// SCANNER_SCAN_TIMEOUT; at SCANNER_SCAN_TIMEOUT the whole process group is killed.
func (r *Runner) exec(ctx context.Context, cacheDir, scanTmp, outputPath, reference string) error {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.ScanTimeout)
	defer cancel()

	args := []string{
		"image",
		"--scanners", "vuln",
		"--format", "json",
		"--output", outputPath,
		"--list-all-pkgs=false",
		"--skip-db-update",
		"--skip-java-db-update",
		"--skip-version-check",
		"--image-src", "remote",
		"--platform", r.cfg.ScanPlatform,
		"--cache-dir", cacheDir,
		"--timeout", trivyTimeout(r.cfg.ScanTimeout).String(),
		"--quiet",
	}
	if r.plainHTTP {
		args = append(args, "--insecure")
	}
	// Trivy's in-memory layer cache lives for this one process: nothing of it
	// is written to disk. The DBs are still read from the cache directory.
	if r.cfg.WorkerCacheBackend == config.CacheBackendMemory {
		args = append(args, "--cache-backend", config.CacheBackendMemory)
	}
	args = append(args, reference)

	cmd := exec.CommandContext(ctx, r.trivy, args...)
	cmd.Env = r.environment(scanTmp)
	stderr := &tailBuffer{limit: stderrTail}
	cmd.Stderr = stderr
	// Trivy and its children get their own process group, killed as a whole.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	err := cmd.Run()
	if err == nil {
		return nil
	}
	tail := r.redact(stderr.String())
	switch {
	case ctx.Err() != nil:
		return &ScanError{Class: FailureTimeout,
			Detail: fmt.Sprintf("Trivy was killed after SCANNER_SCAN_TIMEOUT (%s); stderr: %s", r.cfg.ScanTimeout, tail)}
	case strings.Contains(tail, "context deadline exceeded"):
		// Trivy stopped at its own --timeout.
		return &ScanError{Class: FailureTimeout, Detail: "Trivy timed out; stderr: " + tail}
	case strings.Contains(tail, "no child with platform"):
		return &ScanError{Class: FailurePlatformNotFound,
			Detail: fmt.Sprintf("the image has no manifest for %s (SCANNER_SCAN_PLATFORM); stderr: %s", r.cfg.ScanPlatform, tail)}
	case strings.Contains(tail, "Unable to initialize the Java DB"):
		return &ScanError{Class: FailureJavaDBMissing,
			Detail: "the image has Java archives and no Java DB is installed (set SCANNER_JAVA_DB_SOURCES); stderr: " + tail}
	}
	return &ScanError{Class: FailureExit, Detail: fmt.Sprintf("Trivy failed (%v); stderr: %s", err, tail)}
}

// trivyTimeout is Trivy's own --timeout: a little below the hard limit, so Trivy
// usually stops by itself before it is killed.
func trivyTimeout(scanTimeout time.Duration) time.Duration {
	margin := scanTimeout / 10
	if margin > 30*time.Second {
		margin = 30 * time.Second
	}
	return scanTimeout - margin
}

// environment is Trivy's environment: an allowlist of the scanner's environment
// (never the full one, which holds service and MongoDB secrets) plus the robot
// account in TRIVY_USERNAME / TRIVY_PASSWORD, never on the command line.
func (r *Runner) environment(tmpDir string) []string {
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch {
		case name == "TRIVY_USERNAME" || name == "TRIVY_PASSWORD":
			// Replaced below by the robot account.
		case name == "TMPDIR" && tmpDir != "":
			// Replaced below by the scan's own temp directory.
		case name == "PATH" || name == "HOME" || name == "TMPDIR",
			strings.HasPrefix(name, "TRIVY_"),
			strings.EqualFold(name, "HTTP_PROXY"), strings.EqualFold(name, "HTTPS_PROXY"), strings.EqualFold(name, "NO_PROXY"):
			env = append(env, entry)
		}
	}
	if tmpDir != "" {
		env = append(env, "TMPDIR="+tmpDir)
	}
	if r.cfg.RegistryUsername != "" {
		env = append(env, "TRIVY_USERNAME="+r.cfg.RegistryUsername, "TRIVY_PASSWORD="+r.cfg.RegistryPassword)
	}
	return env
}

// trimLayerCache clears the worker's Trivy layer cache (fanal) when it is
// larger than SCANNER_V2_WORKER_CACHE_MAX. It runs between scans of that worker
// and never touches the DBs. The memory backend has no layer cache on disk.
func (r *Runner) trimLayerCache(logger *slog.Logger, worker string) {
	if r.cfg.WorkerCacheBackend == config.CacheBackendMemory {
		return
	}
	layerCache := filepath.Join(r.workDir, worker, "fanal")
	size, err := r.dirSize(layerCache)
	if err != nil {
		logger.Warn("measuring the worker's layer cache failed", slog.String("error", err.Error()))
		return
	}
	if size <= r.cfg.WorkerCacheMax {
		return
	}
	if err = os.RemoveAll(layerCache); err != nil {
		logger.Warn("clearing the worker's layer cache failed", slog.String("error", err.Error()))
		return
	}
	logger.Info("worker layer cache cleared", slog.String("worker", worker),
		slog.Int64("size_bytes", size), slog.Int64("max_bytes", r.cfg.WorkerCacheMax))
}

// dirSize is the total size of the regular files below path; 0 when it does not exist.
func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.WalkDir(path, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return size, err
}

// CleanTemp removes what scans left in the temp directory (a crash or a kill
// of this process). Call it at startup, before any scan.
func (r *Runner) CleanTemp() error {
	if err := os.RemoveAll(r.tmpDir); err != nil {
		return fmt.Errorf("removing leftover scan files: %w", err)
	}
	return os.MkdirAll(r.tmpDir, 0o700)
}

// redact removes the robot account's password from text.
func (r *Runner) redact(text string) string {
	if r.cfg.RegistryPassword != "" {
		text = strings.ReplaceAll(text, r.cfg.RegistryPassword, "xxxxx")
	}
	return text
}

// replaceSymlink makes link point at target, replacing an existing link with a
// rename (atomic).
func replaceSymlink(target, link string) error {
	newLink := link + ".new"
	_ = os.Remove(newLink)
	if err := os.Symlink(target, newLink); err != nil {
		return fmt.Errorf("linking %s: %w", link, err)
	}
	if err := os.Rename(newLink, link); err != nil {
		return fmt.Errorf("linking %s: %w", link, err)
	}
	return nil
}

// tailBuffer keeps the last limit bytes written to it.
type tailBuffer struct {
	limit int
	data  []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	if len(b.data) > b.limit {
		b.data = b.data[len(b.data)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	return strings.TrimSpace(string(b.data))
}
