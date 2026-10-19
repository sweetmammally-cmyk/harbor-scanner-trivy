package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/metrics"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// scanState is the short answer for a queued or running scan.
type scanState struct {
	ScanID string  `json:"scan_id"`
	State  string  `json:"state"`
	DB     dbBlock `json:"db"`
}

// dbBlock is the db section of a response (DEMAND section 5.1).
type dbBlock struct {
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
	LastUpstreamCheckAt *time.Time `json:"last_upstream_check_at,omitempty"`
	ConfirmedAt         *time.Time `json:"confirmed_at,omitempty"`
	Freshness           string     `json:"freshness"`
}

// postTimeout bounds one POST: the digest resolution (two registry tries) and
// a few MongoDB calls.
func (h *Handler) postTimeout() time.Duration {
	return 2*h.cfg.RegistryTimeout + 4*h.cfg.MongoOperationTimeout
}

// createScan is POST /api/v2/scans (DEMAND sections 5.1 and 6): validate ->
// not ready -> resolve -> active-scan check -> cache -> enqueue.
func (h *Handler) createScan(w http.ResponseWriter, r *http.Request) {
	// The upstream server's write timeout can be shorter than a resolve with its
	// retry; this request extends its own deadline (not possible in all tests).
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.postTimeout() + 5*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), h.postTimeout())
	defer cancel()

	var body scanRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	scan, err := validate(body, time.Now(), h.cfg.DBMaxAgeDefault)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), 0)
		return
	}
	if !h.checkReady(w) {
		return
	}

	resolved, err := h.deps.Registry.Resolve(ctx, registry.Image{Repository: scan.Image.Repository, Name: scan.Image.Name, Tag: scan.Image.Tag})
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	scan.Image.Digest = resolved.Digest
	scan.Image.MediaType = resolved.MediaType
	scan.Reference = resolved.Reference
	scan.ID = store.ScanID(scan.Image)
	logger := slog.With(slog.String("scan_id", scan.ID), slog.String("digest", scan.Image.Digest),
		slog.Any("customer_ids", scan.CustomerIDs), slog.String("request_id", scan.LastRequestID))

	existing, err := h.deps.Scans.Get(ctx, scan.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.writeStoreError(w, logger, err)
		return
	}
	exists := err == nil
	if exists && active(existing) {
		h.answerActive(ctx, w, logger, existing, scan)
		return
	}
	if !body.Force && h.serveFromCache(ctx, w, logger, scan, existing, exists) {
		return
	}

	queued, created, err := h.deps.Queue.Enqueue(ctx, scan)
	switch {
	case errors.Is(err, queue.ErrQueueFull):
		logger.Warn("scan refused, the queue is full")
		writeError(w, http.StatusTooManyRequests, CodeQueueFull, "the scan queue is full", retryQueueFull)
	case errors.Is(err, queue.ErrScanInProgress):
		writeError(w, http.StatusConflict, CodeScanInProgress, "another scan of this image tag is in progress", retryScanning)
	case err != nil:
		h.writeStoreError(w, logger, err)
	case created:
		logger.Info("scan queued", slog.Any("platforms", queued.Options.Platforms), slog.Any("severities", queued.Options.Severity))
		writeJSON(w, http.StatusAccepted, scanState{ScanID: queued.ID, State: queued.State, DB: h.dbBlock(ctx, queued)})
	default:
		// A concurrent request queued the same work first.
		writeJSON(w, http.StatusOK, scanState{ScanID: queued.ID, State: queued.State, DB: h.dbBlock(ctx, queued)})
	}
}

// answerActive answers a request while the tag is queued or scanning: 200 with
// its state when it is the same digest and its scope covers the request (also
// with force; the document is not changed), otherwise 409.
func (h *Handler) answerActive(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, existing, request store.Scan) {
	if existing.Image.Digest == request.Image.Digest && queue.Covers(existing.Options, request.Options) {
		logger.Info("scan joined the running scan of the tag", slog.String("state", existing.State))
		writeJSON(w, http.StatusOK, scanState{ScanID: existing.ID, State: existing.State, DB: h.dbBlock(ctx, existing)})
		return
	}
	writeError(w, http.StatusConflict, CodeScanInProgress, "another scan of this image tag is in progress", retryScanning)
}

// serveFromCache answers a cache hit (DEMAND section 6): the tag's own result
// (renewed), or another tag's result for the same digest (copied into this
// tag's document). It returns false on a miss, and true when it answered,
// also with an error.
func (h *Handler) serveFromCache(ctx context.Context, w http.ResponseWriter, logger *slog.Logger,
	request, existing store.Scan, exists bool) bool {
	local, _ := h.deps.DBState.Get(ctx, "db")
	freshness := local.Freshness(request.Options.MaxDBAge, time.Now())
	want := queue.Want{
		Digest:          request.Image.Digest,
		ScannedPlatform: h.cfg.ScanPlatform,
		TrivyVersion:    h.deps.TrivyVersion(),
		Options:         request.Options,
		DBUpdatedAt:     local.Metadata.UpdatedAt,
	}

	if exists && queue.Serves(existing, want) {
		renewed, err := h.deps.Queue.Renew(ctx, request, request.Image.Digest, freshness)
		if errors.Is(err, store.ErrNotFound) {
			return false // changed by a concurrent request
		}
		if err != nil {
			h.writeStoreError(w, logger, err)
			return true
		}
		h.writeHit(ctx, w, logger, renewed, request, "")
		return true
	}

	// Another tag's result; once more if the source's report vanished in between.
	for try := 0; try < 2; try++ {
		source, err := h.deps.Queue.FindCopySource(ctx, want, request.ID)
		if errors.Is(err, store.ErrNotFound) {
			return false
		}
		if err != nil {
			h.writeStoreError(w, logger, err)
			return true
		}
		report, err := h.deps.Reports.Load(ctx, source)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			h.writeStoreError(w, logger, err)
			return true
		}

		copied := request
		result := *source.Result
		result.Report = nil
		result.ReportGridFSID = nil
		copied.Result = &result
		copied.DB = &store.ScanDB{UpdatedAt: source.DB.UpdatedAt, ManifestDigest: source.DB.ManifestDigest, Freshness: freshness}
		copied.State = store.ScanDone
		save := func(ctx context.Context, scan store.Scan) error { return h.deps.Queue.SaveCopy(ctx, scan, exists) }
		err = store.SaveWithReport(ctx, h.deps.Reports, copied, report, save)
		if errors.Is(err, store.ErrNotFound) {
			return false // changed by a concurrent request
		}
		if err != nil {
			h.writeStoreError(w, logger, err)
			return true
		}
		saved, err := h.deps.Scans.Get(ctx, request.ID)
		if err != nil {
			h.writeStoreError(w, logger, err)
			return true
		}
		h.writeHit(ctx, w, logger, saved, request, source.ID)
		return true
	}
	return false
}

// writeHit answers a cache hit with the result filtered to the request.
func (h *Handler) writeHit(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, scan, request store.Scan, copiedFrom string) {
	report, err := h.deps.Reports.Load(ctx, scan)
	if err != nil {
		h.writeStoreError(w, logger, err)
		return
	}
	view, err := newResultView(scan, report, request.Options.Platforms, request.Options.Severity, h.dbBlock(ctx, scan))
	if err != nil {
		logger.Error("building the result view failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, CodeInternal, "building the result failed", 0)
		return
	}
	view.Cached = true
	view.DBUnchanged = true
	if copiedFrom == "" {
		metrics.ScanFinished(metrics.ResultHit, 0)
	} else {
		metrics.ScanFinished(metrics.ResultCopyHit, 0)
	}
	logger.Info("scan skipped (db unchanged)", slog.String("copied_from", copiedFrom),
		slog.Time("db_updated_at", scan.DB.UpdatedAt), slog.String("freshness", scan.DB.Freshness))
	writeJSON(w, http.StatusOK, view)
}

func active(scan store.Scan) bool {
	return scan.State == store.ScanQueued || scan.State == store.ScanScanning
}

// checkReady answers 503 while the service is stopping, MongoDB is down, the
// schema is not ready or no DB is installed.
func (h *Handler) checkReady(w http.ResponseWriter) bool {
	switch {
	case h.stopping.Load():
		writeError(w, http.StatusServiceUnavailable, CodeNotReady, "the service is shutting down", retryNotReady)
	case !h.deps.StoreUp():
		writeError(w, http.StatusServiceUnavailable, CodeStoreUnavailable, "MongoDB is unavailable", retryNotReady)
	case !h.deps.StoreReady():
		writeError(w, http.StatusServiceUnavailable, CodeNotReady, "the MongoDB schema is not ready", retryNotReady)
	case !h.deps.DBInstalled():
		writeError(w, http.StatusServiceUnavailable, CodeNotReady, "no vulnerability DB is installed yet", retryNotReady)
	default:
		return true
	}
	return false
}

// writeRegistryError maps the registry client's errors (DEMAND section 6.1).
func writeRegistryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, registry.ErrInvalidName):
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid image name", 0)
	case errors.Is(err, registry.ErrImageNotFound):
		writeError(w, http.StatusNotFound, CodeImageNotFound, "the image tag was not found in the registry", 0)
	case errors.Is(err, registry.ErrAuthFailed):
		writeError(w, http.StatusBadGateway, CodeRegistryAuthFailed, "the registry refused the scanner's credentials", 0)
	case errors.Is(err, registry.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, CodeRegistryUnavailable, "the registry is unavailable", retryRegistry)
	default:
		slog.Error("resolving the image digest failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, CodeInternal, "resolving the image digest failed", 0)
	}
}

// writeStoreError answers a failed MongoDB call with 503; the detail is only logged.
func (h *Handler) writeStoreError(w http.ResponseWriter, logger *slog.Logger, err error) {
	logger.Error("a MongoDB call failed", slog.String("error", err.Error()))
	writeError(w, http.StatusServiceUnavailable, CodeStoreUnavailable, "MongoDB is unavailable", retryNotReady)
}

// dbBlock is the db section for a scan document: the stored values of its
// result, or this instance's DB state while the tag has no result yet.
// last_upstream_check_at is always this instance's.
func (h *Handler) dbBlock(ctx context.Context, scan store.Scan) dbBlock {
	local, _ := h.deps.DBState.Get(ctx, "db")
	var block dbBlock
	if !local.LastUpstreamCheckAt.IsZero() {
		checked := local.LastUpstreamCheckAt
		block.LastUpstreamCheckAt = &checked
	}
	if scan.Result != nil && scan.DB != nil {
		updated := scan.DB.UpdatedAt
		block.UpdatedAt = &updated
		block.ConfirmedAt = scan.ConfirmedAt
		block.Freshness = scan.DB.Freshness
		return block
	}
	if !local.Metadata.UpdatedAt.IsZero() {
		updated := local.Metadata.UpdatedAt
		block.UpdatedAt = &updated
	}
	maxAge := scan.Options.MaxDBAge
	if maxAge == 0 {
		maxAge = h.cfg.DBMaxAgeDefault
	}
	block.Freshness = local.Freshness(maxAge, time.Now())
	return block
}
