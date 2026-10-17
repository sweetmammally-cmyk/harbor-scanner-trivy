package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// scanIDPattern is a valid scan_id: a sha256 in lowercase hex.
var scanIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// failureMessages are the short, fixed messages of the failure classes. The
// stored detail (which can hold redacted stderr) is never returned.
var failureMessages = map[string]string{
	runner.FailureTimeout:          "the scan timed out",
	runner.FailureExit:             "Trivy could not scan the image",
	runner.FailureOutputTooLarge:   "the scan output was too large",
	runner.FailureOutputInvalid:    "the scan output could not be read",
	runner.FailureDBMissing:        "no vulnerability DB was installed",
	runner.FailureJavaDBMissing:    "the image has Java files and no Java DB is installed",
	runner.FailurePlatformNotFound: "the image has no manifest for the scan platform",
	queue.FailureWorkerLost:        "the scan's worker stopped too many times",
}

// stateView answers a scan that is queued, scanning or failed (DEMAND 5.2).
type stateView struct {
	ScanID   string        `json:"scan_id"`
	State    string        `json:"state"`
	Image    imageView     `json:"image"`
	DB       dbBlock       `json:"db"`
	Error    *failureView  `json:"error,omitempty"`
	Previous *previousView `json:"previous,omitempty"`
}

type failureView struct {
	Class   string `json:"class"`
	Message string `json:"message"`
}

// previousView is the tag's last good result while it has no new one.
type previousView struct {
	ConfirmedAt *time.Time     `json:"confirmed_at,omitempty"`
	Digest      string         `json:"digest"`
	Summary     map[string]int `json:"summary"`
}

type notFoundView struct {
	ScanID string `json:"scan_id,omitempty"`
	State  string `json:"state"`
}

// getScan is GET /api/v2/scans/{id}: the tag's current state; the result view
// when done. Optional platforms and severity query parameters filter the view.
func (h *Handler) getScan(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if !scanIDPattern.MatchString(id) {
		writeJSON(w, http.StatusNotFound, notFoundView{State: "not_found"})
		return
	}
	platforms, severity, err := normalizeOptions(splitList(r.URL.Query().Get("platforms")), splitList(r.URL.Query().Get("severity")))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), 0)
		return
	}
	if !h.deps.StoreUp() {
		writeError(w, http.StatusServiceUnavailable, CodeStoreUnavailable, "MongoDB is unavailable", retryNotReady)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*h.cfg.MongoOperationTimeout)
	defer cancel()
	logger := slog.With(slog.String("scan_id", id))

	scan, err := h.deps.Scans.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, notFoundView{ScanID: id, State: "not_found"})
		return
	}
	if err != nil {
		h.writeStoreError(w, logger, err)
		return
	}

	// The default view is the full stored scope; a filter must stay inside it.
	if scan.Result != nil {
		scope := store.ScanOptions{Platforms: scan.Result.Platforms, Severity: scan.Result.Severity}
		if len(platforms) == 0 {
			platforms = scope.Platforms
		}
		if len(severity) == 0 {
			severity = scope.Severity
		}
		if !queue.Covers(scope, store.ScanOptions{Platforms: platforms, Severity: severity}) {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest, "the platforms or severities are outside the stored scan", 0)
			return
		}
	}

	if scan.State == store.ScanDone {
		report, err := h.deps.Reports.Load(ctx, scan)
		if err != nil {
			h.writeStoreError(w, logger, err)
			return
		}
		view, err := newResultView(scan, report, platforms, severity, h.dbBlock(ctx, scan))
		if err != nil {
			logger.Error("building the result view failed", slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, CodeInternal, "building the result failed", 0)
			return
		}
		writeJSON(w, http.StatusOK, view)
		return
	}

	view := stateView{
		ScanID: scan.ID,
		State:  scan.State,
		Image:  imageView{Repository: scan.Image.Repository, Name: scan.Image.Name, Tag: scan.Image.Tag, Digest: scan.Image.Digest},
		DB:     h.dbBlock(ctx, scan),
	}
	if scan.Result != nil {
		view.Previous = &previousView{ConfirmedAt: scan.ConfirmedAt, Digest: scan.Result.Digest, Summary: summaryFor(scan.Result, platforms)}
	}
	if scan.State == store.ScanFailed {
		message, found := failureMessages[scan.FailureClass]
		if !found {
			message = "the scan failed"
		}
		view.Error = &failureView{Class: scan.FailureClass, Message: message}
	} else {
		w.Header().Set("Retry-After", strconv.Itoa(retryPoll))
	}
	writeJSON(w, http.StatusOK, view)
}

// splitList splits a comma-separated query value; empty gives nil.
func splitList(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
