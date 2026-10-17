package api

import (
	"net/http"
	"strings"
)

// NotReady returns why the v2 service is not ready (DEMAND section 5.5), or
// nothing when it is. It never calls MongoDB: the state comes from the
// background ping. A degraded DB mode does not make the service unready.
func (h *Handler) NotReady() []string {
	var reasons []string
	if h.stopping.Load() {
		reasons = append(reasons, "the service is shutting down")
	}
	if !h.deps.StoreUp() {
		reasons = append(reasons, "MongoDB is down")
	} else if !h.deps.StoreReady() {
		reasons = append(reasons, "the MongoDB schema is not ready")
	}
	if !h.deps.DBInstalled() {
		reasons = append(reasons, "no Trivy DB is installed")
	}
	if len(h.cfg.JavaDBSources) > 0 && !h.deps.JavaDBInstalled() {
		reasons = append(reasons, "no Java DB is installed")
	}
	if h.deps.TrivyVersion() == "" {
		reasons = append(reasons, "the trivy binary is missing")
	}
	return reasons
}

// ReadyProbe answers 503 while the v2 service is not ready, otherwise it asks
// next (the v1 readiness probe).
func (h *Handler) ReadyProbe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reasons := h.NotReady(); len(reasons) > 0 {
			writeError(w, http.StatusServiceUnavailable, CodeNotReady, strings.Join(reasons, "; "), 0)
			return
		}
		next.ServeHTTP(w, r)
	})
}
