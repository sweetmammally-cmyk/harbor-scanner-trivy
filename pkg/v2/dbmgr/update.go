package dbmgr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

const (
	ModeNormal   = "normal"
	ModeDegraded = "degraded"
)

// dbKind describes one of the DBs we keep in Trivy's cache directory.
type dbKind struct {
	// Name is the directory Trivy reads in its cache directory.
	Name string
	// Files are the files of the DB layer; the first one is the DB file itself.
	Files []string
	// MediaType is the media type of the DB layer in the manifest.
	MediaType string
}

var trivyDB = dbKind{
	Name:      "db",
	Files:     []string{"trivy.db", "metadata.json"},
	MediaType: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
}

// javaDB is Trivy's Java DB (for example ghcr.io/aquasecurity/trivy-java-db:1),
// read from <cache-dir>/java-db.
var javaDB = dbKind{
	Name:      "java-db",
	Files:     []string{"trivy-java.db", "metadata.json"},
	MediaType: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
}

// SourceResult is what happened with one source during an update.
type SourceResult struct {
	Source   string      `json:"source"`
	Precheck CheckResult `json:"precheck"`
	// Answered is true when the pre-check and the upstream check succeeded.
	Answered       bool   `json:"answered"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	Installed      bool   `json:"installed"`
	// FailureClass is the pre-check class, or upstream_error, download_error or install_error.
	FailureClass string `json:"failure_class,omitempty"`
	Error        string `json:"error,omitempty"`
}

// UpdateResult is the outcome of one update run, for the DB state and the API.
type UpdateResult struct {
	// Mode is degraded when no source answered, or when a newer DB was offered
	// but none could be installed.
	Mode string `json:"mode"`
	// ActiveSource is the last source that answered, "" when none did.
	ActiveSource string `json:"active_source,omitempty"`
	// ManifestDigest is the digest of the active DB after the run.
	ManifestDigest string `json:"manifest_digest,omitempty"`
	Installed      bool   `json:"installed"`
	// UpstreamCheckedAt (last_upstream_check_at) is when a source last answered
	// in this run; zero when none did. Diagnostic only.
	UpstreamCheckedAt time.Time `json:"last_upstream_check_at"`
	// ConfirmedCurrentAt (last_confirmed_current_at) is set when the installed
	// digest equalled the answering source's digest, or a new DB was installed.
	// Zero otherwise. Freshness is computed from it.
	ConfirmedCurrentAt time.Time `json:"last_confirmed_current_at"`
	// NewerAvailable is true when a source offered a different DB and none could
	// be installed. It is false when this run installed or confirmed the DB.
	// When no source answered (UpstreamCheckedAt is zero) it says nothing, and
	// the stored flag must be kept.
	NewerAvailable bool `json:"newer_available"`
	// Metadata is the metadata.json of the active DB after the run; zero when there is none.
	Metadata Metadata       `json:"metadata"`
	Sources  []SourceResult `json:"sources"`
}

// update runs one update of a DB (DEMAND section 7.4). For each source in order:
// pre-check, upstream check, then download and install when the digest differs
// from the installed one. It stops at the first source whose digest equals the
// installed one or after an install. A failed source is recorded and the next
// one is tried. When no source answered, the mode is degraded and the existing
// DB is kept. There is no downgrade guard: the first source that answers wins.
func update(ctx context.Context, cfg config.Config, cacheDir string, kind dbKind, sources []config.DBSource) UpdateResult {
	logger := slog.With(slog.String("db", kind.Name))
	installed := installedDigest(cacheDir, kind.Name)
	var result UpdateResult

	// newerNotInstalled is set when a source offered a different DB that could not be installed.
	newerNotInstalled := false

	for _, source := range sources {
		sourceResult := SourceResult{Source: source.String()}
		fail := func(class string, err error) {
			sourceResult.FailureClass = class
			sourceResult.Error = err.Error()
			result.Sources = append(result.Sources, sourceResult)
			logger.Warn("DB source failed", slog.String("source", sourceResult.Source),
				slog.String("failure_class", class), slog.String("error", err.Error()))
		}

		sourceResult.Precheck = Precheck(ctx, source, cfg)
		if !sourceResult.Precheck.OK {
			// Precheck has already logged the failing stage.
			sourceResult.FailureClass = sourceResult.Precheck.FailureClass
			result.Sources = append(result.Sources, sourceResult)
			continue
		}

		client, err := newRegistryClient(source)
		if err != nil {
			fail("upstream_error", err)
			continue
		}
		checkCtx, cancel := context.WithTimeout(ctx, cfg.PrecheckTimeoutManifest)
		manifest, digest, changed, err := checkUpstream(checkCtx, client, installed)
		cancel()
		if err != nil {
			fail("upstream_error", err)
			continue
		}

		sourceResult.Answered = true
		sourceResult.ManifestDigest = digest
		result.ActiveSource = sourceResult.Source
		result.UpstreamCheckedAt = time.Now()
		logger.Info("DB source selected", slog.String("source", sourceResult.Source),
			slog.String("manifest_digest", digest), slog.Bool("changed", changed))

		if !changed {
			result.ManifestDigest = digest
			result.ConfirmedCurrentAt = time.Now()
			newerNotInstalled = false
			result.Sources = append(result.Sources, sourceResult)
			logger.Info("DB is up to date", slog.String("source", sourceResult.Source))
			break
		}
		newerNotInstalled = true

		var layer ociDescriptor
		for _, candidate := range manifest.Layers {
			if candidate.MediaType == kind.MediaType {
				layer = candidate
			}
		}
		if layer.Digest == "" {
			fail("download_error", fmt.Errorf("manifest has no layer of type %s", kind.MediaType))
			continue
		}

		versionDir, err := newVersionDir(cacheDir, kind.Name)
		if err != nil {
			fail("install_error", err)
			continue
		}
		downloadCtx, cancel := context.WithTimeout(ctx, cfg.DBDownloadTimeout)
		start := time.Now()
		err = downloadDB(downloadCtx, client, layer, versionDir, cfg.DBDownloadStallTimeout, kind.Files)
		cancel()
		if err == nil {
			// A DB without a valid metadata.json would break the scan cache: do not install it.
			_, err = readMetadata(versionDir)
		}
		if err != nil {
			_ = os.RemoveAll(versionDir)
			fail("download_error", err)
			continue
		}
		if err = installDB(cacheDir, kind.Name, versionDir, digest); err != nil {
			_ = os.RemoveAll(versionDir)
			fail("install_error", err)
			continue
		}

		sourceResult.Installed = true
		result.Installed = true
		result.ManifestDigest = digest
		result.ConfirmedCurrentAt = time.Now()
		newerNotInstalled = false
		result.Sources = append(result.Sources, sourceResult)
		logger.Info("DB installed", slog.String("source", sourceResult.Source),
			slog.String("manifest_digest", digest), slog.Int64("download_ms", time.Since(start).Milliseconds()))
		break
	}

	if result.ManifestDigest == "" {
		result.ManifestDigest = installedDigest(cacheDir, kind.Name)
	}

	var failures []string
	for _, sourceResult := range result.Sources {
		if sourceResult.FailureClass != "" {
			failures = append(failures, sourceResult.Source+": "+sourceResult.FailureClass)
		}
	}
	switch {
	case result.UpstreamCheckedAt.IsZero():
		result.Mode = ModeDegraded
		logger.Error("all DB sources failed, scanning with existing DB",
			slog.Bool("db_present", dbPresent(cacheDir, kind.Name, kind.Files[0])),
			slog.String("failures", strings.Join(failures, "; ")),
		)
	case newerNotInstalled:
		result.Mode = ModeDegraded
		result.NewerAvailable = true
		logger.Error("newer DB available but could not be installed",
			slog.String("active_source", result.ActiveSource),
			slog.String("failures", strings.Join(failures, "; ")),
		)
	default:
		result.Mode = ModeNormal
	}

	// DB age is for visibility only; it never blocks an install.
	metadata, err := readMetadata(filepath.Join(cacheDir, kind.Name))
	if err == nil {
		result.Metadata = metadata
		age := time.Since(metadata.UpdatedAt)
		if age > cfg.DBAgeWarn {
			logger.Warn("DB is older than SCANNER_DB_AGE_WARN",
				slog.String("db_age", age.Round(time.Minute).String()),
				slog.Time("updated_at", metadata.UpdatedAt),
				slog.String("active_source", result.ActiveSource),
			)
		}
	} else if dbPresent(cacheDir, kind.Name, kind.Files[0]) {
		logger.Warn("cannot read the metadata of the active DB", slog.String("error", err.Error()))
	}

	return result
}
