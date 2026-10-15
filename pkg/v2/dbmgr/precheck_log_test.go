package dbmgr

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogs sends the default slog logger to a buffer for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(defaultLogger) })
	return &logs
}

func assertNoSecretsInLogs(t *testing.T, logs string) {
	t.Helper()
	for _, secret := range []string{"s3cret", "wr0ng", testToken, "user:", "Authorization", "Bearer", "Basic "} {
		assert.NotContains(t, logs, secret)
	}
}

func TestPrecheck_Logs(t *testing.T) {
	t.Run("passing pre-check logs source, route, TLS and every stage", func(t *testing.T) {
		server := startFakeRegistry(t, true, true)
		proxy := startSOCKS5Proxy(t, "user", "s3cret")
		logs := captureLogs(t)

		result := Precheck(context.Background(), registrySource(t, server, "socks5://user:s3cret@"+proxy.addr), testConfig)
		require.True(t, result.OK, "%+v", result)

		lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
		require.Len(t, lines, 7, logs.String()) // started, 5 stages, passed

		assert.Contains(t, lines[0], `"msg":"DB source pre-check started"`)
		assert.Contains(t, lines[0], `"source":"`+server.Listener.Addr().String()+`/aquasec/trivy-db:2|socks5://xxxxx@`+proxy.addr+`"`)
		assert.Contains(t, lines[0], `"route":"socks5 proxy `+proxy.addr+`"`)
		assert.Contains(t, lines[0], `"tls_min_version":"TLS 1.2"`)
		assert.Contains(t, lines[0], `"alpn_offered":"h2,http/1.1"`)
		assert.Contains(t, lines[0], `"allow_http1":false`)

		for i, stage := range []string{"dns", "connect", "tls", "http", "manifest"} {
			assert.Contains(t, lines[i+1], `"level":"INFO"`)
			assert.Contains(t, lines[i+1], `"msg":"DB source pre-check stage"`)
			assert.Contains(t, lines[i+1], `"stage":"`+stage+`"`)
			assert.Contains(t, lines[i+1], `"ok":true`)
		}
		assert.Contains(t, lines[1], `"skipped":true`)
		assert.Contains(t, lines[3], "alpn=h2")
		assert.Contains(t, lines[4], "protocol=HTTP/2.0")

		assert.Contains(t, lines[6], `"msg":"DB source pre-check passed"`)
		assertNoSecretsInLogs(t, logs.String())
	})

	t.Run("failing stage is logged as a warning", func(t *testing.T) {
		server := startFakeRegistry(t, false, false)
		logs := captureLogs(t)

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)
		require.False(t, result.OK)

		assert.Contains(t, logs.String(), `"route":"direct"`)
		assert.Contains(t, logs.String(), `"level":"WARN","msg":"DB source pre-check stage","source":"`)
		assert.Contains(t, logs.String(), `server did not negotiate HTTP/2`)
		assert.Contains(t, logs.String(), `"level":"WARN","msg":"DB source pre-check failed"`)
	})

	t.Run("proxy rejecting credentials does not leak them", func(t *testing.T) {
		server := startFakeRegistry(t, true, true)
		proxy := startHTTPProxy(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:s3cret")))
		logs := captureLogs(t)

		result := Precheck(context.Background(), registrySource(t, server, "http://user:wr0ng@"+proxy.addr), testConfig)
		require.False(t, result.OK)

		assert.Contains(t, logs.String(), "CONNECT returned 407")
		assertNoSecretsInLogs(t, logs.String())
	})
}
