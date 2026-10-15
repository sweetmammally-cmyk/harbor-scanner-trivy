package dbmgr

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// UpdateResults is the outcome of one update run for both DBs.
type UpdateResults struct {
	DB UpdateResult `json:"db"`
	// JavaDB is nil when SCANNER_JAVA_DB_SOURCES is empty: the Java DB is optional.
	JavaDB *UpdateResult `json:"java_db,omitempty"`
}

// Degraded reports whether either DB is in degraded mode.
func (r UpdateResults) Degraded() bool {
	return r.DB.Mode == ModeDegraded || (r.JavaDB != nil && r.JavaDB.Mode == ModeDegraded)
}

// Updater keeps the Trivy DB and the Java DB up to date (DEMAND section 7.2).
// Only one update runs at a time; callers that ask while a run is in progress
// share its results.
type Updater struct {
	// ctx is the service lifetime. Runs use it, so a caller that stops waiting
	// does not cancel a run that others share.
	ctx      context.Context
	cfg      config.Config
	cacheDir string
	store    StateStore

	mu      sync.Mutex
	running *updateRun
}

type updateRun struct {
	done    chan struct{}
	results UpdateResults
}

// NewUpdater returns an updater for the DBs in Trivy's cache directory. After each
// run it saves the state of each DB in store. ctx is the service lifetime: when it
// ends, Run returns and runs stop.
func NewUpdater(ctx context.Context, cfg config.Config, cacheDir string, store StateStore) *Updater {
	return &Updater{ctx: ctx, cfg: cfg, cacheDir: cacheDir, store: store}
}

// Run installs the seed DBs when no DB exists yet, updates at once, and then
// again every SCANNER_DB_CHECK_INTERVAL, or every SCANNER_DB_RETRY_INTERVAL while
// a DB is degraded. It returns when the updater's context ends.
func (u *Updater) Run() {
	u.installSeed(trivyDB, u.cfg.DBSeedDir)
	if len(u.cfg.JavaDBSources) > 0 {
		u.installSeed(javaDB, u.cfg.JavaDBSeedDir)
	}

	for {
		results, err := u.UpdateNow(u.ctx)
		if err != nil {
			return
		}

		next := u.cfg.DBCheckInterval
		if results.Degraded() {
			next = u.cfg.DBRetryInterval
		}
		slog.Info("next DB check scheduled", slog.String("in", next.String()), slog.Bool("degraded", results.Degraded()))

		select {
		case <-u.ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// UpdateNow runs one update of both DBs, or joins the run in progress, and waits
// for its results. waitCtx only limits the waiting: when it ends, UpdateNow
// returns its error and the run goes on.
func (u *Updater) UpdateNow(waitCtx context.Context) (UpdateResults, error) {
	u.mu.Lock()
	run := u.running
	if run == nil {
		run = &updateRun{done: make(chan struct{})}
		u.running = run
		go u.runOnce(run)
	}
	u.mu.Unlock()

	select {
	case <-run.done:
		return run.results, nil
	case <-waitCtx.Done():
		return UpdateResults{}, waitCtx.Err()
	}
}

func (u *Updater) runOnce(run *updateRun) {
	run.results.DB = update(u.ctx, u.cfg, u.cacheDir, trivyDB, u.cfg.DBSources)
	u.saveState(trivyDB.Name, run.results.DB)
	if len(u.cfg.JavaDBSources) > 0 {
		javaResult := update(u.ctx, u.cfg, u.cacheDir, javaDB, u.cfg.JavaDBSources)
		u.saveState(javaDB.Name, javaResult)
		run.results.JavaDB = &javaResult
	}

	u.mu.Lock()
	u.running = nil
	u.mu.Unlock()
	close(run.done)
}

// saveState applies an update result to the stored state of a DB.
func (u *Updater) saveState(db string, result UpdateResult) {
	state, err := u.store.Get(u.ctx, db)
	if err == nil {
		err = u.store.Save(u.ctx, db, state.apply(result))
	}
	if err != nil {
		slog.Error("saving DB state failed", slog.String("db", db), slog.String("error", err.Error()))
	}
}

func (u *Updater) installSeed(kind dbKind, seedDir string) {
	installed, err := installSeed(u.cacheDir, kind.Name, seedDir, kind.Files)
	if err != nil {
		slog.Error("installing seed DB failed", slog.String("db", kind.Name),
			slog.String("seed_dir", seedDir), slog.String("error", err.Error()))
		return
	}
	if installed {
		slog.Info("installed seed DB", slog.String("db", kind.Name), slog.String("seed_dir", seedDir))
	}
}
