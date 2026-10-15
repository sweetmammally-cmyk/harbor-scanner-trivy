package dbmgr

import (
	"context"
	"sync"
	"time"
)

// DBState is what we know about one DB across update runs: the db_state
// document of DEMAND section 10, and the source of GET /api/v2/db.
type DBState struct {
	Mode           string `json:"mode"`
	ActiveSource   string `json:"active_source,omitempty"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	// LastUpstreamCheckAt is when a source last answered. Diagnostic only.
	LastUpstreamCheckAt time.Time `json:"last_upstream_check_at"`
	// LastConfirmedCurrentAt is when the DB was last confirmed current or installed.
	// Freshness is computed from it.
	LastConfirmedCurrentAt time.Time `json:"last_confirmed_current_at"`
	// NewerAvailable is set while a newer DB is known but could not be installed.
	NewerAvailable bool `json:"newer_available"`
	// InstalledAt is when we installed the active DB (our downloaded_at).
	InstalledAt time.Time `json:"installed_at"`
	Metadata    Metadata  `json:"metadata"`
	// LastSources are the per-source results of the last run.
	LastSources []SourceResult `json:"last_sources"`
}

// apply returns the state after an update run. When no source answered, the run
// says nothing about upstream, so the stored active source, check time and
// newer_available are kept.
func (s DBState) apply(result UpdateResult) DBState {
	s.Mode = result.Mode
	s.ManifestDigest = result.ManifestDigest
	s.Metadata = result.Metadata
	s.LastSources = result.Sources

	if !result.UpstreamCheckedAt.IsZero() {
		s.LastUpstreamCheckAt = result.UpstreamCheckedAt
		s.ActiveSource = result.ActiveSource
		s.NewerAvailable = result.NewerAvailable
	}
	if !result.ConfirmedCurrentAt.IsZero() {
		s.LastConfirmedCurrentAt = result.ConfirmedCurrentAt
	}
	if result.Installed {
		s.InstalledAt = result.ConfirmedCurrentAt
	}
	return s
}

// StateStore keeps the state of each DB ("db", "java-db").
// MemoryStateStore is used until the MongoDB store exists (P5-6).
type StateStore interface {
	// Get returns the stored state, or a zero DBState when there is none.
	Get(ctx context.Context, db string) (DBState, error)
	Save(ctx context.Context, db string, state DBState) error
}

// MemoryStateStore is a StateStore in memory. It is lost on restart.
type MemoryStateStore struct {
	mu     sync.Mutex
	states map[string]DBState
}

func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{states: map[string]DBState{}}
}

func (m *MemoryStateStore) Get(_ context.Context, db string) (DBState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[db], nil
}

func (m *MemoryStateStore) Save(_ context.Context, db string, state DBState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[db] = state
	return nil
}
