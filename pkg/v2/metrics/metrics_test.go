package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceHost(t *testing.T) {
	assert.Equal(t, "ghcr.io", SourceHost("ghcr.io/aquasecurity/trivy-db:2|direct"))
	assert.Equal(t, "mirror.local:5000", SourceHost("mirror.local:5000/trivy-db:2|http://xxxxx@proxy:3128|allow-http1"))
}

func TestCollector(t *testing.T) {
	reads := 0
	collector := NewCollector(func() Gauges {
		reads++
		return Gauges{
			MongoUp: true, TrivyVersion: "0.74.0", SchemaVersion: 4, QueueKnown: true,
			Queue: QueueFigures{Depth: 3, OldestQueuedAge: 90 * time.Second, Claims: 10, ClaimDuration: 2 * time.Second, LeaseLosses: 1, ReaperRequeues: 2},
			DBs:   []DBFigures{{DB: "db", Age: time.Hour, ConfirmedAge: time.Minute, Degraded: true}},
		}
	})
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector))

	expected := `
# HELP scanner_v2_queue_depth Queued scans.
# TYPE scanner_v2_queue_depth gauge
scanner_v2_queue_depth 3
# HELP scanner_v2_db_degraded 1 while the DB updater is in degraded mode.
# TYPE scanner_v2_db_degraded gauge
scanner_v2_db_degraded{db="db"} 1
# HELP scanner_v2_build_info Trivy version and schema version.
# TYPE scanner_v2_build_info gauge
scanner_v2_build_info{schema_version="4",trivy_version="0.74.0"} 1
`
	require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(expected),
		"scanner_v2_queue_depth", "scanner_v2_db_degraded", "scanner_v2_build_info"))
	count, err := testutil.GatherAndCount(registry)
	require.NoError(t, err)
	assert.Equal(t, 12, count, "mongo_up, build_info, 2 queue gauges, 4 queue counters, 4 per DB kind")
	assert.Positive(t, reads)

	t.Run("no queue gauges before the first statistics", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		require.NoError(t, registry.Register(NewCollector(func() Gauges { return Gauges{} })))
		count, err := testutil.GatherAndCount(registry, "scanner_v2_queue_depth")
		require.NoError(t, err)
		assert.Zero(t, count)
	})
}

func TestEventMetrics(t *testing.T) {
	before := testutil.ToFloat64(scans.WithLabelValues(ResultHit))
	ScanFinished(ResultHit, 0)
	assert.Equal(t, before+1, testutil.ToFloat64(scans.WithLabelValues(ResultHit)))

	SourceFailed("db", "mirror.local/trivy-db:2|http://xxxxx@proxy:3128", "tcp_timeout")
	assert.Equal(t, 1.0, testutil.ToFloat64(precheckFailures.WithLabelValues("db", "mirror.local", "tcp_timeout")))

	APIRequest("/api/v2/scans", 202)
	assert.Equal(t, 1.0, testutil.ToFloat64(apiRequests.WithLabelValues("/api/v2/scans", "202")))
}

func TestCollector_UnregisterAfterTheOutputChanged(t *testing.T) {
	gauges := Gauges{}
	collector := NewCollector(func() Gauges { return gauges })
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(collector))
	gauges = Gauges{QueueKnown: true, DBs: []DBFigures{{DB: "db"}}}

	assert.True(t, registry.Unregister(collector))
	assert.NoError(t, registry.Register(NewCollector(func() Gauges { return gauges })), "a new service can register again")
}
