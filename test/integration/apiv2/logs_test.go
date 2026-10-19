//go:build integration

package apiv2

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// TestRequiredLogsAndNoSecrets runs the whole stack with a DB source behind a
// proxy with credentials, and checks the required log lines of DEMAND section
// 12 and that no secret reaches a log, a metric or a response body.
func TestRequiredLogsAndNoSecrets(t *testing.T) {
	logs := &lockedBuffer{}
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	defer slog.SetDefault(defaultLogger)
	const proxyUser, proxyPassword = "proxyuser", "proxy-s3cret-value"
	s := startStack(t, func(cfg *config.Config) {
		cfg.DBSources = []config.DBSource{{Repository: "127.0.0.1:1/aquasec/trivy-db:2",
			Proxy: &url.URL{Scheme: "http", User: url.UserPassword(proxyUser, proxyPassword), Host: "127.0.0.1:1"}}}
	})
	s.setDigest("v1", "sha256:1111")

	require.Equal(t, http.StatusAccepted, s.postReady(t, body("v1", `"alpine"`, `"request_id":"req-1"`)).Code)
	s.waitState(t, scanID("v1"), "done")
	require.Equal(t, http.StatusOK, s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, "")).Code)
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "all DB sources failed, scanning with existing DB")
	}, 20*time.Second, 50*time.Millisecond)

	var bodies []string
	for _, path := range []string{"/api/v2/health", "/api/v2/db", "/api/v2/scans", "/api/v2/scans/" + scanID("v1")} {
		bodies = append(bodies, s.do(http.MethodGet, path, "").Body.String())
	}
	scrape := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	bodies = append(bodies, scrape.Body.String())

	text := logs.String()
	for _, line := range []string{
		`"msg":"triggering scan","scan_id":"` + scanID("v1"),
		`"msg":"scan done"`,
		`"scan_ms":`,
		`"msg":"scan skipped (db unchanged)","scan_id":"` + scanID("v1"),
		`"msg":"scan queued","scan_id":"` + scanID("v1"),
		`"request_id":"req-1"`,
		`"msg":"DB source pre-check started"`,
		`"msg":"DB source pre-check stage"`,
		`"msg":"DB source pre-check failed"`,
		`"msg":"all DB sources failed, scanning with existing DB"`,
		`"msg":"request","method":"POST","route":"/api/v2/scans"`,
	} {
		assert.Contains(t, text, line)
	}
	assert.Contains(t, text, `"customer_ids":["cust-1"]`, "structured logs carry the customer ids")
	assert.Contains(t, text, `"digest":"sha256:1111"`)

	for _, secret := range []string{proxyUser, proxyPassword, registryPassword, token, "Bearer "} {
		assert.NotContains(t, text, secret, "logs")
		for i, body := range bodies {
			assert.NotContains(t, body, secret, "response or metrics %d", i)
		}
	}
	assert.NotContains(t, text, "CVE-", "findings are never logged")
}
