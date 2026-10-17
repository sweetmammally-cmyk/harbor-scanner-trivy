// Package api is the direct scan API, /api/v2 (DEMAND section 5).
package api

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// Resolver resolves a tag to its digest; registry.Client in the service.
type Resolver interface {
	Resolve(ctx context.Context, image registry.Image) (registry.Resolved, error)
}

// Deps are what the handler works with. The functions report readiness and
// the Trivy version without calling MongoDB.
type Deps struct {
	Queue    *queue.Queue
	Scans    store.ScanRepository
	Lister   ScanLister
	Reports  store.ReportStore
	Registry Resolver
	// DBState is this instance's DB state, from memory.
	DBState dbmgr.StateStore
	// OtherDBStates reads the other instances' DB states from MongoDB.
	OtherDBStates func(ctx context.Context) ([]store.DBStateDocument, error)
	StoreUp       func() bool
	StoreReady    func() bool
	DBInstalled   func() bool
	TrivyVersion  func() string
}

// Handler serves /api/v2.
type Handler struct {
	cfg      config.Config
	deps     Deps
	router   *mux.Router
	chain    http.Handler
	inflight chan struct{}
	// stopping is set at shutdown: new POSTs get 503 while in-flight requests drain.
	stopping atomic.Bool
}

// NewHandler returns the /api/v2 handler. Every request is logged and needs the
// service token.
func NewHandler(cfg config.Config, deps Deps) *Handler {
	h := &Handler{
		cfg:      cfg,
		deps:     deps,
		router:   mux.NewRouter(),
		inflight: make(chan struct{}, cfg.MaxInflight),
	}
	h.router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, CodeInvalidRequest, "no such endpoint", 0)
	})
	h.router.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, CodeInvalidRequest, "method not allowed", 0)
	})
	h.router.Methods(http.MethodPost).Path("/api/v2/scans").HandlerFunc(h.createScan)
	h.router.Methods(http.MethodGet).Path("/api/v2/scans/{id}").HandlerFunc(h.getScan)
	h.router.Methods(http.MethodGet).Path("/api/v2/scans").HandlerFunc(h.listScans)
	h.router.Methods(http.MethodGet).Path("/api/v2/db").HandlerFunc(h.getDB)
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
