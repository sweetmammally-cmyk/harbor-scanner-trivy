package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// Paging of GET /api/v2/scans.
const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// ScanLister lists scans; store.MongoScans in the service.
type ScanLister interface {
	List(ctx context.Context, filter store.ScanFilter) ([]store.Scan, error)
}

// listQueryParameters are the accepted query parameters; others are 400.
var listQueryParameters = []string{"customer_id", "digest", "repository", "name", "state", "platform", "request_id",
	"from", "to", "limit", "cursor"}

// listCursor is the position after the last item of a page.
type listCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        string    `json:"id"`
}

type listResponse struct {
	Items      []listItem `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// listItem is a scan without findings or report.
type listItem struct {
	ScanID       string         `json:"scan_id"`
	State        string         `json:"state"`
	Image        imageView      `json:"image"`
	CreatedAt    time.Time      `json:"created_at"`
	ConfirmedAt  *time.Time     `json:"confirmed_at,omitempty"`
	CustomerIDs  []string       `json:"customer_ids"`
	CustomerData map[string]any `json:"customer_data,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	Result       *listResult    `json:"result,omitempty"`
	Error        *failureView   `json:"error,omitempty"`
}

// listResult is the stored scope and counts of the tag's last good result.
type listResult struct {
	Digest             string         `json:"digest"`
	Platforms          []string       `json:"platforms"`
	Severity           []string       `json:"severity"`
	ImagePlatformTypes []string       `json:"image_platform_types"`
	Summary            map[string]int `json:"summary"`
	Truncated          bool           `json:"truncated"`
	DBUpdatedAt        time.Time      `json:"db_updated_at"`
	Freshness          string         `json:"freshness"`
}

// listScans is GET /api/v2/scans: filters, newest first, keyset pagination.
func (h *Handler) listScans(w http.ResponseWriter, r *http.Request) {
	filter, err := parseListQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), 0)
		return
	}
	if !h.deps.StoreUp() {
		writeError(w, http.StatusServiceUnavailable, CodeStoreUnavailable, "MongoDB is unavailable", retryNotReady)
		return
	}
	limit := filter.Limit
	filter.Limit = limit + 1 // one more tells whether there is a next page
	scans, err := h.deps.Lister.List(r.Context(), filter)
	if err != nil {
		h.writeStoreError(w, slog.Default(), err)
		return
	}

	response := listResponse{Items: []listItem{}}
	if len(scans) > limit {
		scans = scans[:limit]
		last := scans[limit-1]
		data, _ := json.Marshal(listCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		response.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	for _, scan := range scans {
		item := listItem{
			ScanID:       scan.ID,
			State:        scan.State,
			Image:        imageView{Repository: scan.Image.Repository, Name: scan.Image.Name, Tag: scan.Image.Tag, Digest: scan.Image.Digest},
			CreatedAt:    scan.CreatedAt,
			ConfirmedAt:  scan.ConfirmedAt,
			CustomerIDs:  scan.CustomerIDs,
			CustomerData: scan.CustomerData,
			RequestID:    scan.LastRequestID,
		}
		if scan.Result != nil && scan.DB != nil {
			item.Result = &listResult{
				Digest:             scan.Result.Digest,
				Platforms:          scan.Result.Platforms,
				Severity:           scan.Result.Severity,
				ImagePlatformTypes: scan.Result.ImagePlatformTypes,
				Summary:            scan.Result.Summary,
				Truncated:          scan.Result.Truncated,
				DBUpdatedAt:        scan.DB.UpdatedAt,
				Freshness:          scan.DB.Freshness,
			}
		}
		if scan.State == store.ScanFailed {
			message, found := failureMessages[scan.FailureClass]
			if !found {
				message = "the scan failed"
			}
			item.Error = &failureView{Class: scan.FailureClass, Message: message}
		}
		response.Items = append(response.Items, item)
	}
	writeJSON(w, http.StatusOK, response)
}

// parseListQuery checks the query parameters of GET /api/v2/scans.
func parseListQuery(query url.Values) (store.ScanFilter, error) {
	for name := range query {
		if !slices.Contains(listQueryParameters, name) {
			return store.ScanFilter{}, fmt.Errorf("unknown query parameter %q", name)
		}
	}
	filter := store.ScanFilter{
		CustomerID: query.Get("customer_id"),
		Digest:     query.Get("digest"),
		Repository: query.Get("repository"),
		Name:       query.Get("name"),
		State:      query.Get("state"),
		Platform:   query.Get("platform"),
		RequestID:  query.Get("request_id"),
		Limit:      defaultListLimit,
	}
	if filter.State != "" && !slices.Contains([]string{store.ScanQueued, store.ScanScanning, store.ScanDone, store.ScanFailed}, filter.State) {
		return store.ScanFilter{}, errors.New("state must be queued, scanning, done or failed")
	}
	var err error
	if value := query.Get("from"); value != "" {
		if filter.From, err = time.Parse(time.RFC3339, value); err != nil {
			return store.ScanFilter{}, errors.New("from must be an RFC 3339 time")
		}
	}
	if value := query.Get("to"); value != "" {
		if filter.To, err = time.Parse(time.RFC3339, value); err != nil {
			return store.ScanFilter{}, errors.New("to must be an RFC 3339 time")
		}
	}
	if value := query.Get("limit"); value != "" {
		filter.Limit, err = strconv.Atoi(value)
		if err != nil || filter.Limit < 1 || filter.Limit > maxListLimit {
			return store.ScanFilter{}, fmt.Errorf("limit must be between 1 and %d", maxListLimit)
		}
	}
	if value := query.Get("cursor"); value != "" {
		var cursor listCursor
		data, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.ID == "" {
			return store.ScanFilter{}, errors.New("invalid cursor")
		}
		filter.AfterCreatedAt = cursor.CreatedAt
		filter.AfterID = cursor.ID
	}
	return filter, nil
}
