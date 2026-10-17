package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

// dbResponse is GET /api/v2/db (DEMAND section 5.4).
type dbResponse struct {
	InstanceID     string         `json:"instance_id"`
	DBs            []dbView       `json:"dbs"`
	OtherInstances []instanceView `json:"other_instances"`
	// OtherInstancesError says why other instances are missing (MongoDB down).
	OtherInstancesError string `json:"other_instances_error,omitempty"`
}

type instanceView struct {
	InstanceID string   `json:"instance_id"`
	DBs        []dbView `json:"dbs"`
}

// dbView is one DB kind of one instance. Source names are stored without
// credentials (config.DBSource.String).
type dbView struct {
	Kind                   string               `json:"kind"`
	Mode                   string               `json:"mode"`
	Version                int                  `json:"version"`
	UpdatedAt              *time.Time           `json:"updated_at,omitempty"`
	DownloadedAt           *time.Time           `json:"downloaded_at,omitempty"`
	InstalledAt            *time.Time           `json:"installed_at,omitempty"`
	ManifestDigest         string               `json:"manifest_digest,omitempty"`
	ActiveSource           string               `json:"active_source,omitempty"`
	LastUpstreamCheckAt    *time.Time           `json:"last_upstream_check_at,omitempty"`
	LastConfirmedCurrentAt *time.Time           `json:"last_confirmed_current_at,omitempty"`
	NewerAvailable         bool                 `json:"newer_available"`
	DBAge                  string               `json:"db_age,omitempty"`
	DBAgeSeconds           int64                `json:"db_age_seconds,omitempty"`
	Freshness              string               `json:"freshness"`
	LastSources            []dbmgr.SourceResult `json:"last_sources"`
	// StateUpdatedAt is when another instance last wrote its state.
	StateUpdatedAt *time.Time `json:"state_updated_at,omitempty"`
}

// getDB is GET /api/v2/db: this instance's DB states from memory (so it works
// while MongoDB is down) and the other instances' from MongoDB, best effort.
func (h *Handler) getDB(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	kinds := []string{"db"}
	if len(h.cfg.JavaDBSources) > 0 {
		kinds = append(kinds, "java-db")
	}
	response := dbResponse{InstanceID: h.cfg.InstanceID, DBs: []dbView{}, OtherInstances: []instanceView{}}
	for _, kind := range kinds {
		state, err := h.deps.DBState.Get(r.Context(), kind)
		if err != nil {
			h.writeStoreError(w, slog.Default(), err)
			return
		}
		response.DBs = append(response.DBs, h.newDBView(kind, state, now))
	}

	if !h.deps.StoreUp() {
		response.OtherInstancesError = "MongoDB is unavailable"
		writeJSON(w, http.StatusOK, response)
		return
	}
	documents, err := h.deps.OtherDBStates(r.Context())
	if err != nil {
		slog.Warn("reading other instances' DB states failed", slog.String("error", err.Error()))
		response.OtherInstancesError = "MongoDB is unavailable"
		writeJSON(w, http.StatusOK, response)
		return
	}
	for _, document := range documents {
		view := h.newDBView(document.DB, document.DBState, now)
		view.StateUpdatedAt = timeOrNil(document.UpdatedAt)
		count := len(response.OtherInstances)
		if count == 0 || response.OtherInstances[count-1].InstanceID != document.InstanceID {
			response.OtherInstances = append(response.OtherInstances, instanceView{InstanceID: document.InstanceID})
			count++
		}
		response.OtherInstances[count-1].DBs = append(response.OtherInstances[count-1].DBs, view)
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) newDBView(kind string, state dbmgr.DBState, now time.Time) dbView {
	view := dbView{
		Kind:                   kind,
		Mode:                   state.Mode,
		Version:                state.Metadata.Version,
		UpdatedAt:              timeOrNil(state.Metadata.UpdatedAt),
		DownloadedAt:           timeOrNil(state.Metadata.DownloadedAt),
		InstalledAt:            timeOrNil(state.InstalledAt),
		ManifestDigest:         state.ManifestDigest,
		ActiveSource:           state.ActiveSource,
		LastUpstreamCheckAt:    timeOrNil(state.LastUpstreamCheckAt),
		LastConfirmedCurrentAt: timeOrNil(state.LastConfirmedCurrentAt),
		NewerAvailable:         state.NewerAvailable,
		Freshness:              state.Freshness(h.cfg.DBMaxAgeDefault, now),
		LastSources:            state.LastSources,
	}
	if view.LastSources == nil {
		view.LastSources = []dbmgr.SourceResult{}
	}
	if age := state.Age(now); age > 0 {
		view.DBAge = age.Round(time.Second).String()
		view.DBAgeSeconds = int64(age / time.Second)
	}
	return view
}

// timeOrNil leaves unknown (zero) times out of the JSON.
func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
