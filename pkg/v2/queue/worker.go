package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// Scanner runs one scan; runner.Runner in the service.
type Scanner interface {
	Scan(ctx context.Context, worker string, scan store.Scan, reference string) (store.Scan, bson.M, error)
}

// Refresher refreshes the DB before a scan when it is too old for the request;
// dbmgr.Updater in the service.
type Refresher interface {
	RefreshForScan(ctx context.Context, maxAge time.Duration) (dbmgr.DBState, string, error)
}

// Pool runs SCANNER_QUEUE_WORKERS workers that claim and run queued scans.
type Pool struct {
	queue     *Queue
	scanner   Scanner
	refresher Refresher
	reports   store.ReportStore
	// ready is false while MongoDB is not ready or no DB is installed; workers
	// do not claim then.
	ready func() bool
	// name identifies this replica in the worker names.
	name string
	// completionRetry is how long a completion write is retried. Tests shorten it.
	completionRetry time.Duration
	// running counts the worker goroutines that are running.
	running atomic.Int32
	// jobs is the parent context of running scans; it is cancelled when the
	// shutdown grace period is over, which kills the scans.
	jobs       context.Context
	cancelJobs context.CancelFunc
}

// NewPool returns the worker pool of this replica.
func NewPool(queue *Queue, scanner Scanner, refresher Refresher, reports store.ReportStore, ready func() bool, name string) *Pool {
	jobs, cancelJobs := context.WithCancel(context.Background())
	return &Pool{
		queue:           queue,
		scanner:         scanner,
		refresher:       refresher,
		reports:         reports,
		ready:           ready,
		name:            name,
		completionRetry: 2 * time.Minute,
		jobs:            jobs,
		cancelJobs:      cancelJobs,
	}
}

// Run runs the workers until ctx ends (SIGTERM). Then no new scan is claimed;
// running scans may finish within SCANNER_SHUTDOWN_GRACE, after which they are
// killed and their leases released, so another replica takes them at once.
// Run returns when every worker has stopped.
func (p *Pool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < p.queue.cfg.QueueWorkers; i++ {
		worker := fmt.Sprintf("%s/worker-%d", p.name, i)
		wg.Add(1)
		p.running.Add(1)
		go func() {
			defer wg.Done()
			defer p.running.Add(-1)
			p.work(ctx, worker)
		}()
	}
	stopped := make(chan struct{})
	go func() {
		wg.Wait()
		close(stopped)
	}()

	select {
	case <-stopped:
		return
	case <-ctx.Done():
	}
	select {
	case <-stopped:
	case <-time.After(p.queue.cfg.ShutdownGrace):
		slog.Warn("shutdown grace period over, killing running scans", slog.String("grace", p.queue.cfg.ShutdownGrace.String()))
		p.cancelJobs()
		<-stopped
	}
	p.cancelJobs()
}

// Running is the number of workers running (0 before Run and after it returns).
func (p *Pool) Running() int {
	return int(p.running.Load())
}

// work claims and runs scans until ctx ends. It does not claim while the
// service is not ready.
func (p *Pool) work(ctx context.Context, worker string) {
	for ctx.Err() == nil {
		if !p.ready() {
			p.wait(ctx)
			continue
		}
		scan, err := p.queue.Claim(ctx, worker)
		if errors.Is(err, ErrNoJob) {
			p.wait(ctx)
			continue
		}
		if err != nil {
			slog.Error("claiming a scan failed", slog.String("worker", worker), slog.String("error", err.Error()))
			p.wait(ctx)
			continue
		}
		p.process(scan, worker)
	}
}

// wait sleeps for the poll interval with up to 50% jitter, or until an enqueue
// in this replica wakes it, or ctx ends.
func (p *Pool) wait(ctx context.Context) {
	interval := p.queue.cfg.QueuePollInterval
	interval += time.Duration(rand.Int64N(int64(interval)/2 + 1))
	select {
	case <-ctx.Done():
	case <-p.queue.wake:
	case <-time.After(interval):
	}
}

// process runs one claimed scan. While it runs, a heartbeat extends the lease;
// if the lease is lost, the scan's context is cancelled, which kills Trivy, and
// the result is discarded.
func (p *Pool) process(scan store.Scan, worker string) {
	logger := slog.With(slog.String("scan_id", scan.ID), slog.String("worker", worker), slog.Int("attempt", scan.Attempt))
	jobCtx, cancelJob := context.WithCancel(p.jobs)
	defer cancelJob()

	var lost bool
	heartbeatDone := make(chan struct{})
	stopHeartbeat := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(p.queue.cfg.QueueLease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ticker.C:
				err := p.queue.Heartbeat(jobCtx, scan)
				if errors.Is(err, ErrLeaseLost) {
					lost = true
					cancelJob()
					return
				}
				if err != nil {
					logger.Warn("heartbeat failed, will retry", slog.String("error", err.Error()))
				}
			}
		}
	}()

	maxAge := scan.Options.MaxDBAge
	if maxAge == 0 {
		maxAge = p.queue.cfg.DBMaxAgeDefault
	}
	// The freshness at scan start, against the request's max_db_age, is stored with the result.
	_, freshness, err := p.refresher.RefreshForScan(jobCtx, maxAge)
	if err != nil {
		logger.Warn("on-demand DB refresh failed, scanning with the current DB", slog.String("error", err.Error()))
	}
	finished, report, scanErr := p.scanner.Scan(jobCtx, worker, scan, scan.Reference)

	close(stopHeartbeat)
	<-heartbeatDone
	if lost {
		p.queue.metrics.leaseLost()
		logger.Warn("the scan's lease was lost, its result is discarded")
		return
	}

	// Killed at the end of the shutdown grace: back to the queue, attempt not counted.
	if p.jobs.Err() != nil {
		err = p.queue.Release(context.Background(), scan)
		p.logWriteError(logger, err)
		if err == nil {
			logger.Info("scan released at shutdown, it goes back to the queue")
		}
		return
	}

	if scanErr != nil {
		class := "internal_error"
		var classified *runner.ScanError
		if errors.As(scanErr, &classified) {
			class = classified.Class
		}
		err = p.retry(func() error { return p.queue.Fail(context.Background(), finished, class, scanErr.Error()) })
		p.logWriteError(logger, err)
		if err == nil {
			p.queue.metrics.scanFinished(true)
		}
		return
	}

	finished.DB.Freshness = freshness
	save := func(ctx context.Context, scan store.Scan) error {
		return p.retry(func() error { return p.queue.Complete(ctx, scan) })
	}
	err = store.SaveWithReport(context.Background(), p.reports, finished, report, save)
	p.logWriteError(logger, err)
	if err == nil {
		p.queue.metrics.scanFinished(false)
	}
}

// retry runs a completion write until it succeeds, the lease is lost, or
// completionRetry has passed, waiting longer between tries.
func (p *Pool) retry(write func() error) error {
	deadline := time.Now().Add(p.completionRetry)
	pause := time.Second
	for {
		err := write()
		if err == nil || errors.Is(err, ErrLeaseLost) || time.Now().Add(pause).After(deadline) {
			return err
		}
		time.Sleep(pause)
		pause = min(pause*2, 15*time.Second)
	}
}

func (p *Pool) logWriteError(logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, ErrLeaseLost):
		p.queue.metrics.leaseLost()
		logger.Warn("the scan's lease was lost before its result was written, the result is discarded")
	case err != nil:
		logger.Error("writing the scan's result failed; the reaper will requeue it", slog.String("error", err.Error()))
	}
}
