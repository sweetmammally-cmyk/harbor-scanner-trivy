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
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// CheckTrivy runs `trivy --version` and keeps the version, which is stored with
// each scan. It runs at startup; readiness is false while it fails (P10-2).
func (r *Runner) CheckTrivy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.trivy, "--version")
	cmd.Env = r.environment("")
	out, err := cmd.Output()
	if err != nil {
		r.setVersion("")
		return fmt.Errorf("running %s --version: %w", r.trivy, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if version, found := strings.CutPrefix(line, "Version: "); found {
			r.setVersion(strings.TrimSpace(version))
			return nil
		}
	}
	r.setVersion("")
	return fmt.Errorf("%s --version printed no version", r.trivy)
}

func (r *Runner) setVersion(version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.version = version
}

// Version is the Trivy version found by CheckTrivy; empty when Trivy is missing.
func (r *Runner) Version() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.version
}

// Ready reports whether Trivy was found.
func (r *Runner) Ready() bool {
	return r.Version() != ""
}

// Scan runs one scan of reference (host/repository/name@digest) for the scan's
// platforms and severities (DEMAND sections 6 and 6.2). It records every
// platform of the image in the platforms collection, and returns the scan with
// its new Result and DB (without freshness) and the report to store with
// store.SaveWithReport. On failure the error is a *ScanError with its class and
// the scan is returned unchanged. The queue sets the state, the freshness and
// the other timings.
func (r *Runner) Scan(ctx context.Context, worker string, scan store.Scan, reference string) (store.Scan, bson.M, error) {
	logger := slog.With(
		slog.String("scan_id", scan.ID),
		slog.String("digest", scan.Image.Digest),
		slog.Any("customer_ids", scan.CustomerIDs),
		slog.Any("platforms", scan.Options.Platforms),
		slog.Any("severities", scan.Options.Severity),
		slog.String("trivy_version", r.Version()),
	)
	start := time.Now()
	// Between this worker's scans, keep its layer cache under the limit.
	defer r.trimLayerCache(logger, worker)

	outputPath, db, err := r.runTrivy(ctx, logger, worker, reference)
	if err != nil {
		logScanFailure(logger, err, start)
		return scan, nil, err
	}
	// The output lives in the scan's temp directory: remove it all.
	defer os.RemoveAll(filepath.Dir(outputPath))
	trivyDone := time.Now()

	output, err := os.Open(outputPath)
	if err != nil {
		err = &ScanError{Class: FailureOutputInvalid, Detail: err.Error()}
		logScanFailure(logger, err, start)
		return scan, nil, err
	}
	result, err := parseResult(output, scan.Options.Platforms, scan.Options.Severity, r.cfg.ScanMaxFindings)
	_ = output.Close()
	if err != nil {
		logScanFailure(logger, err, start)
		return scan, nil, err
	}

	// Recording platforms is secondary: a failure is logged and the scan goes on.
	if err = r.platforms.Seen(ctx, result.ImagePlatforms, scan.Image.Digest, time.Now()); err != nil {
		logger.Error("recording the image's platforms failed", slog.String("error", err.Error()))
	}

	scan.Result = &store.ScanResult{
		Digest:             scan.Image.Digest,
		Platforms:          scan.Options.Platforms,
		Severity:           scan.Options.Severity,
		ScannedPlatform:    r.cfg.ScanPlatform,
		TrivyVersion:       r.Version(),
		ImagePlatformTypes: result.ImagePlatforms,
		Summary:            result.Summary,
		SummaryByPlatform:  result.SummaryByPlatform,
		Truncated:          result.Truncated,
	}
	scan.DB = &store.ScanDB{UpdatedAt: db.UpdatedAt, ManifestDigest: db.ManifestDigest}
	scan.ScanMS = time.Since(start).Milliseconds()

	findings := result.Findings
	if findings == nil {
		findings = []Finding{}
	}
	report := bson.M{"findings": findings}

	logger.Info("scan done",
		slog.Int64("scan_ms", scan.ScanMS),
		slog.Int64("trivy_ms", trivyDone.Sub(start).Milliseconds()),
		slog.Int64("parse_ms", time.Since(trivyDone).Milliseconds()),
		slog.Any("summary", result.Summary),
		slog.Int("findings_stored", len(result.Findings)),
		slog.Bool("truncated", result.Truncated),
		slog.Any("platforms_found", result.PlatformsFound),
		slog.Any("platforms_not_found", result.PlatformsNotFound),
	)
	return scan, report, nil
}

func logScanFailure(logger *slog.Logger, err error, start time.Time) {
	class := "internal_error"
	var scanErr *ScanError
	if errors.As(err, &scanErr) {
		class = scanErr.Class
	}
	logger.Warn("scan failed", slog.String("failure_class", class), slog.String("error", err.Error()),
		slog.Int64("scan_ms", time.Since(start).Milliseconds()))
}
