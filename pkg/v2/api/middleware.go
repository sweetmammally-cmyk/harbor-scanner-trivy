package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// maxBodyBytes is the largest request body read.
const maxBodyBytes = 1 << 20

// requestIDPattern is a valid X-Request-ID (and request_id).
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// statusRecorder keeps the status code for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

// Unwrap lets http.ResponseController reach the connection (write deadlines).
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// logRequests accepts or generates X-Request-ID, returns it, and logs one line
// per request: method, route template, status, duration and request id. Bodies
// and headers are never logged.
func (h *Handler) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		if !requestIDPattern.MatchString(requestID) {
			requestID = newRequestID()
		}
		r.Header.Set("X-Request-ID", requestID)
		w.Header().Set("X-Request-ID", requestID)

		route := "unmatched"
		var match mux.RouteMatch
		if h.router.Match(r, &match) && match.Route != nil {
			if template, err := match.Route.GetPathTemplate(); err == nil {
				route = template
			}
		}

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		slog.Info("request",
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", recorder.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("request_id", requestID))
	})
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// authenticate requires "Authorization: Bearer <token>". The hashes are
// compared in constant time; the token is never logged.
func (h *Handler) authenticate(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(h.cfg.AuthToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		got := sha256.Sum256([]byte(token))
		if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scanner-v2"`)
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "a valid bearer token is required", 0)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitInflight lets at most SCANNER_V2_MAX_INFLIGHT POSTs run at once.
func (h *Handler) limitInflight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case h.inflight <- struct{}{}:
			defer func() { <-h.inflight }()
			next.ServeHTTP(w, r)
		default:
			writeError(w, http.StatusTooManyRequests, CodeTooManyRequests, "too many requests in flight", retryInflight)
		}
	})
}

// decodeJSON reads the request body into v: application/json only, at most
// 1 MiB, no unknown fields, nothing after the object. On failure it writes the
// error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, CodeInvalidRequest, "Content-Type must be application/json", 0)
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(v)
	if err == nil && decoder.Decode(&struct{}{}) != io.EOF {
		err = errors.New("unexpected data after the JSON object")
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, CodeInvalidRequest, fmt.Sprintf("the body is larger than %d bytes", maxBodyBytes), 0)
		return false
	case err != nil:
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "invalid JSON body: "+err.Error(), 0)
		return false
	}
	return true
}
