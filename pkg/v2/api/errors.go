package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// Error codes of the v2 API (DEMAND section 5.0). Messages never contain
// secrets, paths or stderr.
const (
	CodeInvalidRequest      = "invalid_request"
	CodeUnauthorized        = "unauthorized"
	CodeImageNotFound       = "image_not_found"
	CodeRegistryAuthFailed  = "registry_auth_failed"
	CodeRegistryUnavailable = "registry_unavailable"
	CodeQueueFull           = "queue_full"
	CodeScanInProgress      = "scan_in_progress"
	CodeNotReady            = "not_ready"
	CodeStoreUnavailable    = "store_unavailable"
	CodeInternal            = "internal"
)

// Retry-After values, in seconds.
const (
	retryInflight  = 1
	retryPoll      = 2
	retryScanning  = 5
	retryQueueFull = 10
	retryRegistry  = 10
	retryNotReady  = 10
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeJSON writes v as the JSON response body with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("writing a response failed", slog.String("error", err.Error()))
	}
}

// writeError writes the one error shape. retryAfter > 0 adds a Retry-After header.
func writeError(w http.ResponseWriter, status int, code, message string, retryAfter int) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}
