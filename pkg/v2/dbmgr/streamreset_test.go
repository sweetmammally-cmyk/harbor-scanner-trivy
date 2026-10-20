package dbmgr

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/metrics"
)

// TestUpdater_StreamReset: an HTTP/2 stream reset during a download is the
// failure class stream_reset in the logs, the state's per-source results (the
// rows of db_checks) and the failure metric; the next source installs the DB.
func TestUpdater_StreamReset(t *testing.T) {
	now := time.Now()
	layer := dbLayer(t, strings.Repeat("resetting source db ", 2000), now)
	resetting := startFakeOCIRegistry(t, layer)
	serveBlob(resetting, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(layer[:len(layer)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // RST_STREAM on HTTP/2
	})
	good := startFakeOCIRegistry(t, dbLayer(t, "good db", now))
	cfg := updateConfig
	cfg.DBSources = []config.DBSource{resetting.source(t, "direct"), good.source(t, "direct")}
	store := NewMemoryStateStore()
	logs := captureLogs(t)
	host := metrics.SourceHost(cfg.DBSources[0].String())
	before := precheckFailures(t, host)

	results, err := NewUpdater(context.Background(), cfg, t.TempDir(), store).UpdateNow(context.Background())

	require.NoError(t, err)
	assert.True(t, results.DB.Installed)
	assert.Equal(t, "stream_reset", results.DB.Sources[0].FailureClass)
	state, err := store.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, "stream_reset", state.LastSources[0].FailureClass, "stored with the state and its db_checks rows")
	assert.Contains(t, logs.String(), `"msg":"DB source failed","db":"db","source":"`+cfg.DBSources[0].String()+`","failure_class":"stream_reset"`)
	assert.Equal(t, before+1, precheckFailures(t, host))
}

// precheckFailures reads scanner_v2_db_precheck_failures_total for the trivy DB,
// the source host and class stream_reset from the default registry.
func precheckFailures(t *testing.T, host string) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "scanner_v2_db_precheck_failures_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["db"] == "db" && labels["source"] == host && labels["class"] == "stream_reset" {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}
