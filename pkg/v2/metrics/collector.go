package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Gauges are the values read at scrape time. Read must not call MongoDB: the
// queue figures are the last cached statistics (refreshed in the background).
type Gauges struct {
	MongoUp       bool
	TrivyVersion  string
	SchemaVersion int
	// QueueKnown is false until the first queue statistics were read.
	QueueKnown bool
	Queue      QueueFigures
	DBs        []DBFigures
}

// QueueFigures are the queue statistics of DEMAND section 9.
type QueueFigures struct {
	Depth           int64
	OldestQueuedAge time.Duration
	Claims          int64
	ClaimDuration   time.Duration
	LeaseLosses     int64
	ReaperRequeues  int64
}

// DBFigures describe one DB kind ("db" or "java-db") of this instance.
type DBFigures struct {
	DB             string
	Age            time.Duration
	ConfirmedAge   time.Duration
	Degraded       bool
	NewerAvailable bool
}

var (
	mongoUpDesc        = prometheus.NewDesc("scanner_v2_mongo_up", "1 while the MongoDB ping succeeds.", nil, nil)
	buildInfoDesc      = prometheus.NewDesc("scanner_v2_build_info", "Trivy version and schema version.", []string{"trivy_version", "schema_version"}, nil)
	queueDepthDesc     = prometheus.NewDesc("scanner_v2_queue_depth", "Queued scans.", nil, nil)
	oldestQueuedDesc   = prometheus.NewDesc("scanner_v2_queue_oldest_age_seconds", "Age of the oldest queued scan.", nil, nil)
	claimsDesc         = prometheus.NewDesc("scanner_v2_queue_claims_total", "Claim calls of this replica.", nil, nil)
	claimSecondsDesc   = prometheus.NewDesc("scanner_v2_queue_claim_seconds_total", "Total duration of the claim calls (latency = this / claims).", nil, nil)
	leaseLossesDesc    = prometheus.NewDesc("scanner_v2_queue_lease_losses_total", "Scans whose lease this replica lost.", nil, nil)
	reaperRequeuesDesc = prometheus.NewDesc("scanner_v2_queue_reaper_requeues_total", "Scans this replica's reaper put back in the queue.", nil, nil)
	dbAgeDesc          = prometheus.NewDesc("scanner_v2_db_age_seconds", "Age of the installed DB (now minus its UpdatedAt).", []string{"db"}, nil)
	dbConfirmedAgeDesc = prometheus.NewDesc("scanner_v2_db_confirmed_age_seconds", "Time since the DB was last confirmed current.", []string{"db"}, nil)
	dbDegradedDesc     = prometheus.NewDesc("scanner_v2_db_degraded", "1 while the DB updater is in degraded mode.", []string{"db"}, nil)
	dbNewerDesc        = prometheus.NewDesc("scanner_v2_db_newer_available", "1 while a newer DB is known but not installed.", []string{"db"}, nil)
)

// Collector exports Gauges at each scrape.
type Collector struct {
	read func() Gauges
}

// NewCollector returns a collector that calls read at each scrape.
func NewCollector(read func() Gauges) *Collector {
	return &Collector{read: read}
}

// Describe sends the fixed descriptors (not derived from Collect, whose output
// changes), so Unregister finds the collector again.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{mongoUpDesc, buildInfoDesc, queueDepthDesc, oldestQueuedDesc, claimsDesc,
		claimSecondsDesc, leaseLossesDesc, reaperRequeuesDesc, dbAgeDesc, dbConfirmedAgeDesc, dbDegradedDesc, dbNewerDesc} {
		ch <- desc
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	gauges := c.read()
	ch <- prometheus.MustNewConstMetric(mongoUpDesc, prometheus.GaugeValue, boolValue(gauges.MongoUp))
	ch <- prometheus.MustNewConstMetric(buildInfoDesc, prometheus.GaugeValue, 1, gauges.TrivyVersion, strconv.Itoa(gauges.SchemaVersion))
	if gauges.QueueKnown {
		ch <- prometheus.MustNewConstMetric(queueDepthDesc, prometheus.GaugeValue, float64(gauges.Queue.Depth))
		ch <- prometheus.MustNewConstMetric(oldestQueuedDesc, prometheus.GaugeValue, gauges.Queue.OldestQueuedAge.Seconds())
	}
	ch <- prometheus.MustNewConstMetric(claimsDesc, prometheus.CounterValue, float64(gauges.Queue.Claims))
	ch <- prometheus.MustNewConstMetric(claimSecondsDesc, prometheus.CounterValue, gauges.Queue.ClaimDuration.Seconds())
	ch <- prometheus.MustNewConstMetric(leaseLossesDesc, prometheus.CounterValue, float64(gauges.Queue.LeaseLosses))
	ch <- prometheus.MustNewConstMetric(reaperRequeuesDesc, prometheus.CounterValue, float64(gauges.Queue.ReaperRequeues))
	for _, db := range gauges.DBs {
		ch <- prometheus.MustNewConstMetric(dbAgeDesc, prometheus.GaugeValue, db.Age.Seconds(), db.DB)
		ch <- prometheus.MustNewConstMetric(dbConfirmedAgeDesc, prometheus.GaugeValue, db.ConfirmedAge.Seconds(), db.DB)
		ch <- prometheus.MustNewConstMetric(dbDegradedDesc, prometheus.GaugeValue, boolValue(db.Degraded), db.DB)
		ch <- prometheus.MustNewConstMetric(dbNewerDesc, prometheus.GaugeValue, boolValue(db.NewerAvailable), db.DB)
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
