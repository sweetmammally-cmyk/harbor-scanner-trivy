// Package metrics holds the Prometheus metrics of the v2 service (DEMAND
// section 12), on the adapter's /metrics. Labels never carry customer ids,
// digests, repositories or tags; a source label is the registry host only.
package metrics

import (
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Results of the scans counter.
const (
	ResultDone    = "done"
	ResultFailed  = "failed"
	ResultHit     = "hit"
	ResultCopyHit = "copy_hit"
)

// durationBuckets cover 1s to about 34 minutes.
var durationBuckets = prometheus.ExponentialBuckets(1, 2, 12)

var (
	scans = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scanner_v2_scans_total", Help: "Scan requests answered by a scan (done, failed) or by the cache (hit, copy_hit).",
	}, []string{"result"})
	scanDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "scanner_v2_scan_duration_seconds", Help: "Duration of completed scans.", Buckets: durationBuckets,
	})
	queueWait = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "scanner_v2_queue_wait_seconds", Help: "Time from queued to claimed.", Buckets: durationBuckets,
	})
	apiRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scanner_v2_api_requests_total", Help: "API requests by route template and status.",
	}, []string{"route", "status"})
	apiInflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "scanner_v2_api_inflight_requests", Help: "API requests being handled.",
	})
	dbUpdateRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scanner_v2_db_update_runs_total", Help: "DB update runs by DB kind and resulting mode.",
	}, []string{"db", "mode"})
	precheckFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scanner_v2_db_precheck_failures_total", Help: "Failed DB source checks by DB kind, source host and failure class.",
	}, []string{"db", "source", "class"})
)

func init() {
	prometheus.MustRegister(scans, scanDuration, queueWait, apiRequests, apiInflight, dbUpdateRuns, precheckFailures)
}

// ScanFinished counts a scan request by result; duration is observed for done scans.
func ScanFinished(result string, duration time.Duration) {
	scans.WithLabelValues(result).Inc()
	if result == ResultDone {
		scanDuration.Observe(duration.Seconds())
	}
}

// ScanClaimed observes how long a scan waited in the queue.
func ScanClaimed(wait time.Duration) {
	queueWait.Observe(wait.Seconds())
}

// APIRequest counts a finished API request by route template and status.
func APIRequest(route string, status int) {
	apiRequests.WithLabelValues(route, strconv.Itoa(status)).Inc()
}

// APIInflight adds delta to the in-flight requests.
func APIInflight(delta float64) {
	apiInflight.Add(delta)
}

// DBUpdateRun counts an update run of a DB kind by its resulting mode.
func DBUpdateRun(db, mode string) {
	dbUpdateRuns.WithLabelValues(db, mode).Inc()
}

// SourceFailed counts a failed source of an update run by its failure class.
// source is "repository|route" (credential-free); only its host is a label.
func SourceFailed(db, source, class string) {
	precheckFailures.WithLabelValues(db, SourceHost(source), class).Inc()
}

// SourceHost is the registry host of a source "host/path:tag|route".
func SourceHost(source string) string {
	repository, _, _ := strings.Cut(source, "|")
	host, _, _ := strings.Cut(repository, "/")
	return host
}
