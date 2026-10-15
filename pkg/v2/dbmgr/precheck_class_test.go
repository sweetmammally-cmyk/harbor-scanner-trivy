package dbmgr

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// startAfterClientHello starts a TCP server that reads the client's first bytes
// (the TLS ClientHello) and then calls then.
func startAfterClientHello(t *testing.T, then func(conn net.Conn)) string {
	return listen(t, func(conn net.Conn) {
		buf := make([]byte, 1024)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		then(conn)
	})
}

func directSource(t *testing.T, addr string) config.DBSource {
	t.Helper()
	sources, err := config.ParseDBSources(addr + "/aquasec/trivy-db:2|direct")
	require.NoError(t, err)
	return sources[0]
}

func TestPrecheck_FailureClass(t *testing.T) {
	t.Run("tls_reset: server resets after the ClientHello", func(t *testing.T) {
		addr := startAfterClientHello(t, func(conn net.Conn) {
			// Linger 0 makes Close send a TCP RST instead of a FIN.
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
		})

		result := Precheck(context.Background(), directSource(t, addr), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, []string{"dns", "connect", "tls"}, stageNames(result))
		assert.Equal(t, "tls_reset", result.Stages[2].Class, result.Stages[2].Detail)
		assert.Equal(t, "tls_reset", result.FailureClass)
	})

	t.Run("tls_timeout: server goes silent after the ClientHello", func(t *testing.T) {
		done := make(chan struct{})
		t.Cleanup(func() { close(done) })
		addr := startAfterClientHello(t, func(conn net.Conn) {
			<-done
		})

		cfg := testConfig
		cfg.PrecheckTimeoutTLS = 100 * time.Millisecond
		result := Precheck(context.Background(), directSource(t, addr), cfg)

		assert.False(t, result.OK)
		assert.Equal(t, "tls_timeout", result.FailureClass, result.Stages[len(result.Stages)-1].Detail)
	})

	t.Run("tls_alert: server answers the ClientHello with an alert", func(t *testing.T) {
		addr := startAfterClientHello(t, func(conn net.Conn) {
			// TLS record: type alert (21), version 1.2, length 2, level fatal (2), handshake_failure (40).
			_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, 40})
		})

		result := Precheck(context.Background(), directSource(t, addr), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, "tls_alert", result.FailureClass, result.Stages[len(result.Stages)-1].Detail)
		assert.Contains(t, result.Stages[2].Detail, "handshake failure")
	})

	t.Run("tls_cert_invalid: certificate from an unknown CA", func(t *testing.T) {
		server := startFakeRegistry(t, true, false)
		rootCAs = x509.NewCertPool()

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, "tls_cert_invalid", result.FailureClass)
		detail := result.Stages[2].Detail
		assert.Contains(t, detail, "certificate signed by unknown authority")
		assert.Contains(t, detail, `subject="O=Acme Co"`)
		assert.Contains(t, detail, `issuer="O=Acme Co"`)
		expires := server.Certificate().NotAfter.UTC().Format(time.RFC3339)
		assert.Contains(t, detail, "expires="+expires)
	})

	t.Run("tcp_refused: nothing listens on the port", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := listener.Addr().String()
		require.NoError(t, listener.Close())

		result := Precheck(context.Background(), directSource(t, addr), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, []string{"dns", "connect"}, stageNames(result))
		assert.Equal(t, "tcp_refused", result.FailureClass)
	})

	t.Run("tcp_timeout: blackholed proxy", func(t *testing.T) {
		blackhole := startBlackhole(t)
		sources, err := config.ParseDBSources("ghcr.io/aquasecurity/trivy-db:2|socks5://" + blackhole)
		require.NoError(t, err)

		cfg := testConfig
		cfg.PrecheckTimeoutConnect = 100 * time.Millisecond
		result := Precheck(context.Background(), sources[0], cfg)

		assert.False(t, result.OK)
		assert.Equal(t, "tcp_timeout", result.FailureClass)
	})

	t.Run("dns_failure: unknown host", func(t *testing.T) {
		result := Precheck(context.Background(), directSource(t, "does-not-exist.invalid"), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, []string{"dns"}, stageNames(result))
		assert.Equal(t, "dns_failure", result.FailureClass)
	})

	t.Run("http2_not_negotiated", func(t *testing.T) {
		server := startFakeRegistry(t, false, false)

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		assert.Equal(t, "http2_not_negotiated", result.FailureClass)
	})

	t.Run("manifest_error and manifest_timeout", func(t *testing.T) {
		server := startFakeRegistry(t, true, false)
		next := server.Config.Handler
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/manifests/hang") {
				<-r.Context().Done()
				return
			}
			next.ServeHTTP(w, r)
		})

		missing := registrySource(t, server, "direct")
		missing.Repository = strings.Replace(missing.Repository, "trivy-db:2", "trivy-db:3", 1)
		assert.Equal(t, "manifest_error", Precheck(context.Background(), missing, testConfig).FailureClass)

		hanging := registrySource(t, server, "direct")
		hanging.Repository = strings.Replace(hanging.Repository, "trivy-db:2", "trivy-db:hang", 1)
		cfg := testConfig
		cfg.PrecheckTimeoutManifest = 100 * time.Millisecond
		assert.Equal(t, "manifest_timeout", Precheck(context.Background(), hanging, cfg).FailureClass)
	})

	t.Run("passing pre-check has no class", func(t *testing.T) {
		server := startFakeRegistry(t, true, false)

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		require.True(t, result.OK)
		assert.Empty(t, result.FailureClass)
		for _, stage := range result.Stages {
			assert.Empty(t, stage.Class, stage.Stage)
		}
	})

	t.Run("class is in the log", func(t *testing.T) {
		addr := startAfterClientHello(t, func(conn net.Conn) {
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
		})
		logs := captureLogs(t)

		Precheck(context.Background(), directSource(t, addr), testConfig)

		assert.Contains(t, logs.String(), `"stage":"tls","ok":false,"skipped":false,"class":"tls_reset"`)
		assert.Contains(t, logs.String(), `"msg":"DB source pre-check failed","source":"`+addr+`/aquasec/trivy-db:2|direct","failure_class":"tls_reset"`)
	})
}
