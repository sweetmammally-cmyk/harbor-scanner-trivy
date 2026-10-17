// Package service starts and stops the v2 direct scan service in the order of
// DEMAND section 5.6, so cmd/scanner-trivy only needs a few lines.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// disconnectTimeout bounds closing the MongoDB connection at shutdown.
const disconnectTimeout = 10 * time.Second

// Service is the running v2 service.
type Service struct {
	handler *api.Handler
	client  *store.Client

	stopMonitor func()
	stopUpdater func()
	updaterDone chan struct{}
	stopPool    func()
	poolDone    chan struct{}
	stopReaper  func()
}

// Start starts the v2 service: the store client and its monitor (which ensures
// the schema once MongoDB is up), the DB updater, the Trivy check, the workers
// and the reaper. The caller then serves Handler. MongoDB being down is not an
// error: the service is not ready until it is up.
func Start(cfg config.Config, trivyPath string) (*Service, error) {
	client, err := store.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating the MongoDB client: %w", err)
	}
	registryClient, err := registry.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating the registry client: %w", err)
	}
	s := &Service{client: client, updaterDone: make(chan struct{}), poolDone: make(chan struct{})}

	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	s.stopMonitor = stopMonitor
	go client.Monitor(monitorCtx, store.PingInterval)

	dbDir := filepath.Join(cfg.CacheDir, "trivy")
	dbState := store.NewDBStateStore(client, cfg.InstanceID, dbDir)
	updaterCtx, stopUpdater := context.WithCancel(context.Background())
	s.stopUpdater = stopUpdater
	updater := dbmgr.NewUpdater(updaterCtx, cfg, dbDir, dbState)
	go func() {
		defer close(s.updaterDone)
		updater.Run()
	}()

	scanner := runner.NewRunner(cfg, trivyPath, dbDir, filepath.Join(cfg.CacheDir, "workers"), store.NewMongoPlatforms(client))
	if err = scanner.CheckTrivy(context.Background()); err != nil {
		slog.Error("Trivy is not usable; the v2 service is not ready", slog.String("error", err.Error()))
	}

	q := queue.New(client, cfg)
	reports := store.NewMongoReports(client, store.ReportInlineLimit)
	workersReady := func() bool { return client.Ready() && updater.DBInstalled() && scanner.Ready() }
	pool := queue.NewPool(q, scanner, updater, reports, workersReady, cfg.InstanceID)
	poolCtx, stopPool := context.WithCancel(context.Background())
	s.stopPool = stopPool
	go func() {
		defer close(s.poolDone)
		pool.Run(poolCtx)
	}()
	reaperCtx, stopReaper := context.WithCancel(context.Background())
	s.stopReaper = stopReaper
	go q.RunReaper(reaperCtx, queue.ReapInterval)

	s.handler = api.NewHandler(cfg, api.Deps{
		Queue:           q,
		Scans:           store.NewMongoScans(client),
		Lister:          store.NewMongoScans(client),
		Reports:         reports,
		Registry:        registryClient,
		DBState:         dbState,
		OtherDBStates:   dbState.Others,
		StoreUp:         client.Up,
		StoreReady:      client.Ready,
		DBInstalled:     updater.DBInstalled,
		JavaDBInstalled: updater.JavaDBInstalled,
		TrivyVersion:    scanner.Version,
	})
	slog.Info("v2 direct scan service started", slog.String("instance_id", cfg.InstanceID),
		slog.Int("workers", cfg.QueueWorkers))
	return s, nil
}

// Handler serves /api/v2/.
func (s *Service) Handler() http.Handler {
	return s.handler
}

// Routes puts the v2 service in front of the Harbor adapter's handler v1:
// /api/v2/ goes to v2, /probe/ready also needs v2 to be ready, and everything
// else (liveness included) is v1's, unchanged.
func (s *Service) Routes(v1 http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v2/", s.handler)
	mux.Handle("/probe/ready", s.handler.ReadyProbe(v1))
	mux.Handle("/", v1)
	return mux
}

// StopAccepting makes the API not ready. Call it before the HTTP server's Shutdown.
func (s *Service) StopAccepting() {
	s.handler.StopAccepting()
}

// Stop stops the service after the HTTP server has drained: workers stop
// claiming and get the shutdown grace, then running scans are killed and
// released; then the reaper, the updater and the MongoDB connection stop.
func (s *Service) Stop() {
	s.stopPool()
	<-s.poolDone
	s.stopReaper()
	s.stopUpdater()
	<-s.updaterDone
	s.stopMonitor()
	ctx, cancel := context.WithTimeout(context.Background(), disconnectTimeout)
	defer cancel()
	if err := s.client.Disconnect(ctx); err != nil {
		slog.Warn("closing the MongoDB connection failed", slog.String("error", err.Error()))
	}
	slog.Info("v2 direct scan service stopped")
}
