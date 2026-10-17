// Package api is the direct scan API, /api/v2 (DEMAND section 5).
package api

import (
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// Handler serves /api/v2.
type Handler struct {
	cfg      config.Config
	router   *mux.Router
	chain    http.Handler
	inflight chan struct{}
	// stopping is set at shutdown: new POSTs get 503 while in-flight requests drain.
	stopping atomic.Bool
}

// NewHandler returns the /api/v2 handler. Every request is logged and needs the
// service token.
func NewHandler(cfg config.Config) *Handler {
	h := &Handler{
		cfg:      cfg,
		router:   mux.NewRouter(),
		inflight: make(chan struct{}, cfg.MaxInflight),
	}
	h.router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, CodeInvalidRequest, "no such endpoint", 0)
	})
	h.router.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, CodeInvalidRequest, "method not allowed", 0)
	})
	h.chain = h.logRequests(h.authenticate(h.limitInflight(h.router)))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.chain.ServeHTTP(w, r)
}

// StopAccepting makes the API not ready (shutdown, DEMAND section 5.6).
func (h *Handler) StopAccepting() {
	h.stopping.Store(true)
}
