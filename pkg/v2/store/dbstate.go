package store

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

// MaxBufferedDBChecks bounds the db_checks kept in memory while MongoDB is down.
const MaxBufferedDBChecks = 1000

// DBStateStore is the dbmgr.StateStore of the service (DEMAND section 10). Memory
// comes first: reads never touch MongoDB, so the DB updater keeps running while
// MongoDB is down. Writes to db_state (one document per instance and DB) and
// db_checks happen when MongoDB is ready: after each Save and, through
// Client.OnReady, each time MongoDB comes back.
type DBStateStore struct {
	client     *Client
	instanceID string
	checks     DBCheckRepository
	// maxChecks bounds the buffer; tests make it small.
	maxChecks int

	// flushMu lets one Flush run at a time; mu guards the fields below.
	flushMu sync.Mutex
	mu      sync.Mutex
	states  map[string]dbmgr.DBState
	// unwritten are the DBs whose state is not written to MongoDB yet.
	unwritten map[string]bool
	buffer    []DBCheck
	dropped   int
}

// NewDBStateStore returns the state store of this instance and registers its
// Flush to run each time MongoDB becomes ready.
func NewDBStateStore(client *Client, instanceID string) *DBStateStore {
	s := &DBStateStore{
		client:     client,
		instanceID: instanceID,
		checks:     NewMongoDBChecks(client),
		maxChecks:  MaxBufferedDBChecks,
		states:     map[string]dbmgr.DBState{},
		unwritten:  map[string]bool{},
	}
	client.OnReady(s.Flush)
	return s
}

// Get returns the state from memory.
func (s *DBStateStore) Get(_ context.Context, db string) (dbmgr.DBState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[db], nil
}

// Save keeps the state in memory and buffers one db_checks row per source of the
// run (each Save is one update run), then writes them if MongoDB is ready. It
// never fails: what is not written now is written by a later Flush.
func (s *DBStateStore) Save(ctx context.Context, db string, state dbmgr.DBState) error {
	s.mu.Lock()
	s.states[db] = state
	s.unwritten[db] = true
	// The run started with the pre-check of its first source.
	var runStartedAt time.Time
	if len(state.LastSources) > 0 {
		runStartedAt = state.LastSources[0].Precheck.StartedAt
	}
	for _, source := range state.LastSources {
		at := source.Precheck.StartedAt
		if at.IsZero() {
			at = time.Now()
		}
		s.bufferCheck(DBCheck{
			ID:           DBCheckID(s.instanceID, db, runStartedAt, source.Source),
			InstanceID:   s.instanceID,
			DB:           db,
			At:           at,
			SourceResult: source,
		})
	}
	s.mu.Unlock()

	if s.client.Ready() {
		s.Flush(ctx)
	}
	return nil
}

// DBCheckID is the _id of a db_checks row: "<instance_id>:<db>:<run_started_at>:<source>".
// The source is already redacted (DBSource.String).
func DBCheckID(instanceID, db string, runStartedAt time.Time, source string) string {
	return instanceID + ":" + db + ":" + runStartedAt.UTC().Format(time.RFC3339Nano) + ":" + source
}

// bufferCheck adds a check, dropping the oldest when the buffer is full.
// The caller holds mu.
func (s *DBStateStore) bufferCheck(check DBCheck) {
	if len(s.buffer) >= s.maxChecks {
		s.buffer = s.buffer[1:]
		s.dropped++
	}
	s.buffer = append(s.buffer, check)
}

// Flush writes the unwritten states and the buffered checks to MongoDB. What
// fails stays in memory for the next Flush.
func (s *DBStateStore) Flush(ctx context.Context) {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	// Take the work out under the lock, write without it, so Get and Save never
	// wait for MongoDB.
	s.mu.Lock()
	states := map[string]dbmgr.DBState{}
	for db := range s.unwritten {
		states[db] = s.states[db]
	}
	s.unwritten = map[string]bool{}
	checks := s.buffer
	s.buffer = nil
	dropped := s.dropped
	s.dropped = 0
	s.mu.Unlock()

	if dropped > 0 {
		slog.Warn("db_checks were dropped while MongoDB was down, the buffer was full",
			slog.Int("dropped", dropped), slog.Int("buffer_size", s.maxChecks))
	}

	for db, state := range states {
		if err := s.writeState(ctx, db, state); err != nil {
			slog.Error("writing DB state to MongoDB failed, will retry", slog.String("db", db), slog.String("error", err.Error()))
			s.mu.Lock()
			s.unwritten[db] = true
			s.mu.Unlock()
		}
	}

	if err := s.checks.Add(ctx, checks); err != nil {
		slog.Error("writing db_checks to MongoDB failed, will retry", slog.Int("count", len(checks)), slog.String("error", err.Error()))
		// Put them back before the checks buffered meanwhile, which are newer.
		s.mu.Lock()
		newer := s.buffer
		s.buffer = nil
		for _, check := range checks {
			s.bufferCheck(check)
		}
		for _, check := range newer {
			s.bufferCheck(check)
		}
		s.mu.Unlock()
	}
}

func (s *DBStateStore) writeState(ctx context.Context, db string, state dbmgr.DBState) error {
	ctx, cancel := s.client.OperationContext(ctx)
	defer cancel()
	document := DBStateDocument{ID: s.instanceID + ":" + db, InstanceID: s.instanceID, DB: db, UpdatedAt: time.Now(), DBState: state}
	_, err := s.client.Database().Collection(CollectionDBState).ReplaceOne(ctx,
		bson.D{{Key: "_id", Value: document.ID}}, document, options.Replace().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("writing db_state %s: %w", document.ID, err)
	}
	return nil
}

// Load reads this instance's stored states at startup (before the updater runs).
// When a stored digest differs from the digest installed on disk, the stored
// confirmation (last_confirmed_current_at, newer_available) is ignored: the disk
// is the source of truth. States already in memory are kept.
func (s *DBStateStore) Load(ctx context.Context, cacheDir string) error {
	ctx, cancel := s.client.OperationContext(ctx)
	defer cancel()
	cursor, err := s.client.Database().Collection(CollectionDBState).Find(ctx, bson.D{{Key: "instance_id", Value: s.instanceID}})
	if err != nil {
		return fmt.Errorf("loading db_state: %w", err)
	}
	var documents []DBStateDocument
	if err = cursor.All(ctx, &documents); err != nil {
		return fmt.Errorf("loading db_state: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, document := range documents {
		if _, found := s.states[document.DB]; found {
			continue
		}
		state := document.DBState
		onDisk := dbmgr.InstalledDigest(cacheDir, document.DB)
		if state.ManifestDigest != onDisk {
			slog.Warn("stored DB state does not match the DB on disk, ignoring its confirmation",
				slog.String("db", document.DB), slog.String("stored_digest", state.ManifestDigest),
				slog.String("disk_digest", onDisk))
			state.ManifestDigest = onDisk
			state.LastConfirmedCurrentAt = time.Time{}
			state.NewerAvailable = false
		}
		s.states[document.DB] = state
	}
	return nil
}

var _ dbmgr.StateStore = (*DBStateStore)(nil)
