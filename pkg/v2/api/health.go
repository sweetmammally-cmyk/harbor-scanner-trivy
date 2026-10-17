package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
)

// Health statuses (DEMAND section 5.5).
const (
	healthOK        = "ok"
	healthDegraded  = "degraded"
	healthUnhealthy = "unhealthy"
)

// Failure-rate rule: degraded above this share of failures in this replica's
// last queue.RecentWindow scans, once there are at least minRecentScans.
const (
	maxFailureRate = 0.5
	minRecentScans = 10
)

type healthResponse struct {
	Status      string         `json:"status"`
	InstanceID  string         `json:"instance_id"`
	Checks      []healthCheck  `json:"checks"`
	DBs         []dbView       `json:"dbs"`
	Queue       *queueView     `json:"queue,omitempty"`
	RecentScans recentView     `json:"recent_scans"`
	Instances   []instanceView `json:"other_instances"`
	// InstancesError says why other instances are missing (MongoDB down).
	InstancesError string `json:"other_instances_error,omitempty"`
}

// healthCheck is one rule; Detail is short and never holds secrets, paths or stderr.
type healthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type queueView struct {
	Depth                  int64 `json:"depth"`
	OldestQueuedAgeSeconds int64 `json:"oldest_queued_age_seconds"`
	Workers                int   `json:"workers"`
}

type recentView struct {
	Window int `json:"window"`
	Done   int `json:"done"`
	Failed int `json:"failed"`
}

// getHealth is GET /api/v2/health: ok and degraded answer 200, unhealthy 503.
func (h *Handler) getHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*h.cfg.MongoOperationTimeout)
	defer cancel()
	response := h.health(ctx, time.Now())
	status := http.StatusOK
	if response.Status == healthUnhealthy {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, response)
}

func (h *Handler) health(ctx context.Context, now time.Time) healthResponse {
	response := healthResponse{InstanceID: h.cfg.InstanceID, Checks: []healthCheck{}}
	add := func(name, status, detail string) {
		response.Checks = append(response.Checks, healthCheck{Name: name, Status: status, Detail: detail})
	}

	if reasons := h.NotReady(); len(reasons) > 0 {
		add("ready", healthUnhealthy, strings.Join(reasons, "; "))
	} else {
		add("ready", healthOK, "")
	}
	workers := h.deps.WorkersRunning()
	if workers == 0 {
		add("workers", healthUnhealthy, "no worker is running")
	} else {
		add("workers", healthOK, fmt.Sprintf("%d running", workers))
	}

	for _, kind := range []string{"db", "java-db"} {
		if kind == "java-db" && len(h.cfg.JavaDBSources) == 0 {
			continue
		}
		state, _ := h.deps.DBState.Get(ctx, kind)
		status, detail := h.dbHealth(state, now)
		add(kind, status, detail)
	}
	response.DBs, _ = h.localDBViews(ctx, now)

	if h.deps.StoreUp() {
		stats, err := h.deps.QueueStats(ctx)
		if err != nil {
			add("queue", healthDegraded, "queue statistics are unavailable")
		} else {
			response.Queue = &queueView{Depth: stats.Depth, OldestQueuedAgeSeconds: int64(stats.OldestQueuedAge / time.Second), Workers: workers}
			if workers > 0 && stats.OldestQueuedAge > h.cfg.HealthQueueStuckAfter {
				add("queue", healthDegraded, fmt.Sprintf("the oldest queued scan has waited %s", stats.OldestQueuedAge.Round(time.Second)))
			} else {
				add("queue", healthOK, "")
			}
		}
	}

	recent := h.deps.RecentScans()
	response.RecentScans = recentView{Window: queue.RecentWindow, Done: recent.Done, Failed: recent.Failed}
	total := recent.Done + recent.Failed
	if total >= minRecentScans && float64(recent.Failed) > maxFailureRate*float64(total) {
		add("recent_scans", healthDegraded, fmt.Sprintf("%d of the last %d scans failed", recent.Failed, total))
	} else {
		add("recent_scans", healthOK, "")
	}

	response.Instances, response.InstancesError = h.otherInstances(ctx, now)

	response.Status = healthOK
	for _, check := range response.Checks {
		if check.Status == healthUnhealthy {
			response.Status = healthUnhealthy
		} else if check.Status == healthDegraded && response.Status == healthOK {
			response.Status = healthDegraded
		}
	}
	return response
}

// dbHealth is degraded for a degraded mode, a newer DB that is not installed,
// a stale DB (default max age) or a DB older than SCANNER_DB_AGE_WARN.
func (h *Handler) dbHealth(state dbmgr.DBState, now time.Time) (string, string) {
	var problems []string
	if state.Mode == dbmgr.ModeDegraded {
		problems = append(problems, "degraded mode: no DB source answered or the newer DB could not be installed")
	}
	if state.NewerAvailable {
		problems = append(problems, "a newer DB is available but not installed")
	}
	if state.Freshness(h.cfg.DBMaxAgeDefault, now) == dbmgr.FreshnessStale {
		problems = append(problems, "stale for the default max age "+h.cfg.DBMaxAgeDefault.String())
	}
	if age := state.Age(now); age > h.cfg.DBAgeWarn {
		problems = append(problems, "older than "+h.cfg.DBAgeWarn.String())
	}
	if len(problems) > 0 {
		return healthDegraded, strings.Join(problems, "; ")
	}
	return healthOK, ""
}
