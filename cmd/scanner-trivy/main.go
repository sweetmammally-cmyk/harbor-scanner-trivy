package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	v1 "github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/redisx"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/scan"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
	v2config "github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/service"
)

var (
	// Default wise GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: etc.LogLevel(),
	}))
	slog.SetDefault(logger)

	info := etc.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	ctx := context.Background()
	if err := run(ctx, info); err != nil {
		slog.Error("Unexpected error:", slog.String("Error", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, info etc.BuildInfo) error {
	slog.Info("Starting harbor-scanner-trivy", slog.String("version", info.Version),
		slog.String("commit", info.Commit), slog.String("built_at", info.Date),
	)

	config, err := etc.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}
	if err = etc.Check(config); err != nil {
		return fmt.Errorf("checking config: %w", err)
	}

	rdb, err := redisx.NewClient(config.RedisPool)
	if err != nil {
		return fmt.Errorf("constructing connection pool: %w", err)
	}

	wrapper := trivy.NewWrapper(config.Trivy, ext.DefaultAmbassador)
	store := redis.NewStore(config.RedisStore, rdb)
	controller := scan.NewController(store, wrapper, scan.NewTransformer(&scan.SystemClock{}))
	enqueuer := queue.NewEnqueuer(config.JobQueue, rdb, store)
	worker := queue.NewWorker(config.JobQueue, rdb, controller)

	apiHandler := v1.NewAPIHandler(info, config, enqueuer, store, wrapper)

	// The direct scan API (v2) is routed only when it is enabled.
	v2Config, err := v2config.GetConfig()
	if err != nil {
		return fmt.Errorf("getting v2 config: %w", err)
	}
	var v2 *service.Service
	if v2Config.Enabled {
		v2, err = service.Start(v2Config, "trivy")
		if err != nil {
			return fmt.Errorf("starting the v2 service: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/api/v2/", v2.Handler())
		mux.Handle("/", apiHandler)
		apiHandler = mux
	}

	apiServer, err := api.NewServer(config.API, apiHandler)
	if err != nil {
		return fmt.Errorf("new api server: %w", err)
	}

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		slog.Debug("Trapped os signal", slog.String("signal", captured.String()))

		if v2 != nil {
			v2.StopAccepting()
		}
		apiServer.Shutdown()
		if v2 != nil {
			v2.Stop()
		}
		worker.Stop()
		_ = rdb.Close()

		close(shutdownComplete)
	}()

	worker.Start(ctx)
	apiServer.ListenAndServe()

	<-shutdownComplete
	return nil
}
