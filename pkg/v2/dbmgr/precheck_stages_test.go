package dbmgr

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

const (
	testToken          = "t0ken-s3cret"
	testManifestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

var testConfig = config.Config{
	PrecheckTimeoutDNS:      time.Second,
	PrecheckTimeoutConnect:  time.Second,
	PrecheckTimeoutTLS:      time.Second,
	PrecheckTimeoutHTTP:     time.Second,
	PrecheckTimeoutManifest: time.Second,
	PrecheckTimeoutTotal:    5 * time.Second,
}

// startFakeRegistry starts a TLS registry serving the manifest of aquasec/trivy-db:2.
// With requireToken it asks for a Bearer token like ghcr.io does.
// It replaces rootCAs so the pre-check trusts the test certificate.
func startFakeRegistry(t *testing.T, enableHTTP2 bool, requireToken bool) *httptest.Server {
	t.Helper()

	var server *httptest.Server
	challenge := func(w http.ResponseWriter) {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="https://`+server.Listener.Addr().String()+`/token",service="fake",scope="repository:aquasec/trivy-db:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			http.NotFound(w, r)
			return
		}
		if requireToken {
			challenge(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/aquasec/trivy-db/manifests/2", func(w http.ResponseWriter, r *http.Request) {
		if requireToken && r.Header.Get("Authorization") != "Bearer "+testToken {
			challenge(w)
			return
		}
		w.Header().Set("Docker-Content-Digest", testManifestDigest)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "repository:aquasec/trivy-db:pull" || r.URL.Query().Get("service") != "fake" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"token":"` + testToken + `"}`))
	})

	server = httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = enableHTTP2
	server.StartTLS()
	t.Cleanup(server.Close)

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	rootCAs = pool
	t.Cleanup(func() { rootCAs = nil })

	return server
}

func registrySource(t *testing.T, server *httptest.Server, route string) config.DBSource {
	t.Helper()
	value := server.Listener.Addr().String() + "/aquasec/trivy-db:2|" + route
	sources, err := config.ParseDBSources(value)
	require.NoError(t, err)
	return sources[0]
}

func stageNames(result CheckResult) []string {
	var names []string
	for _, stage := range result.Stages {
		names = append(names, stage.Stage)
	}
	return names
}

func TestPrecheck_Direct(t *testing.T) {
	t.Run("HTTP/2 registry without token", func(t *testing.T) {
		server := startFakeRegistry(t, true, false)

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		require.True(t, result.OK, "%+v", result)
		assert.Equal(t, []string{"dns", "connect", "tls", "http", "manifest"}, stageNames(result))
		assert.Contains(t, result.Stages[0].Detail, "127.0.0.1 -> 127.0.0.1")
		assert.Contains(t, result.Stages[2].Detail, "alpn=h2")
		assert.Contains(t, result.Stages[2].Detail, "version=TLS 1.3")
		assert.Equal(t, "protocol=HTTP/2.0 status=200", result.Stages[3].Detail)
		assert.Equal(t, "protocol=HTTP/2.0 status=200 digest="+testManifestDigest, result.Stages[4].Detail)
		assert.Greater(t, result.Duration, time.Duration(0))
	})

	t.Run("HTTP/2 registry with anonymous token", func(t *testing.T) {
		server := startFakeRegistry(t, true, true)

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		require.True(t, result.OK, "%+v", result)
		assert.Equal(t, "protocol=HTTP/2.0 status=401", result.Stages[3].Detail)
		assert.Equal(t, "protocol=HTTP/2.0 status=200 digest="+testManifestDigest, result.Stages[4].Detail)

		printed, err := json.Marshal(result)
		require.NoError(t, err)
		assert.NotContains(t, string(printed), testToken, "the token must never be stored in a result")
	})

	t.Run("HTTP/1.1 registry fails by default", func(t *testing.T) {
		server := startFakeRegistry(t, false, false)

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, []string{"dns", "connect", "tls", "http"}, stageNames(result))
		assert.Contains(t, result.Stages[2].Detail, "alpn=http/1.1", "the negotiated protocol is always recorded")
		assert.False(t, result.Stages[3].OK)
		assert.Contains(t, result.Stages[3].Detail, `server did not negotiate HTTP/2 (alpn="http/1.1")`)
		assert.Contains(t, result.Stages[3].Detail, "allow-http1")
	})

	t.Run("HTTP/1.1 registry passes with allow-http1", func(t *testing.T) {
		server := startFakeRegistry(t, false, true)

		result := Precheck(context.Background(), registrySource(t, server, "direct|allow-http1"), testConfig)

		require.True(t, result.OK, "%+v", result)
		assert.Equal(t, "protocol=HTTP/1.1 status=401", result.Stages[3].Detail)
		assert.Equal(t, "protocol=HTTP/1.1 status=200 digest="+testManifestDigest, result.Stages[4].Detail)
	})

	t.Run("missing manifest fails the manifest stage", func(t *testing.T) {
		server := startFakeRegistry(t, true, false)
		source := registrySource(t, server, "direct")
		source.Repository = strings.Replace(source.Repository, "trivy-db:2", "trivy-db:3", 1)

		result := Precheck(context.Background(), source, testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, []string{"dns", "connect", "tls", "http", "manifest"}, stageNames(result))
		assert.Equal(t, "GET manifest aquasec/trivy-db:3 returned status 404 (protocol=HTTP/2.0)", result.Stages[4].Detail)
	})

	t.Run("untrusted certificate fails the tls stage", func(t *testing.T) {
		server := startFakeRegistry(t, true, false)
		rootCAs = x509.NewCertPool()

		result := Precheck(context.Background(), registrySource(t, server, "direct"), testConfig)

		assert.False(t, result.OK)
		assert.Equal(t, []string{"dns", "connect", "tls"}, stageNames(result))
		assert.Contains(t, result.Stages[2].Detail, "certificate")
	})

	t.Run("registry that accepts TCP and never answers stops at the tls timeout", func(t *testing.T) {
		blackhole := startBlackhole(t)
		sources, err := config.ParseDBSources(blackhole + "/aquasec/trivy-db:2|direct")
		require.NoError(t, err)

		cfg := testConfig
		cfg.PrecheckTimeoutTLS = 100 * time.Millisecond
		start := time.Now()
		result := Precheck(context.Background(), sources[0], cfg)

		assert.False(t, result.OK)
		assert.Less(t, time.Since(start), 2*time.Second)
		assert.Equal(t, []string{"dns", "connect", "tls"}, stageNames(result))
		assert.Contains(t, result.Stages[2].Detail, "stage timeout 100ms exceeded")
	})
}

func TestPrecheck_Proxy(t *testing.T) {
	t.Run("HTTP proxy", func(t *testing.T) {
		server := startFakeRegistry(t, true, true)
		proxy := startHTTPProxy(t, "")

		result := Precheck(context.Background(), registrySource(t, server, "http://"+proxy.addr), testConfig)

		require.True(t, result.OK, "%+v", result)
		assert.True(t, result.Stages[0].Skipped, "dns is skipped for a proxy route")
		assert.Contains(t, result.Stages[1].Detail, "via http proxy "+proxy.addr)
		assert.Contains(t, proxy.targets(), server.Listener.Addr().String())
	})

	t.Run("SOCKS5 proxy with credentials", func(t *testing.T) {
		server := startFakeRegistry(t, true, true)
		proxy := startSOCKS5Proxy(t, "user", "s3cret")

		result := Precheck(context.Background(), registrySource(t, server, "socks5://user:s3cret@"+proxy.addr), testConfig)

		require.True(t, result.OK, "%+v", result)
		assert.True(t, result.Stages[0].Skipped)
		assert.Equal(t, "dns", result.Stages[0].Stage)
		assert.Contains(t, result.Stages[1].Detail, "via socks5 proxy "+proxy.addr)

		printed, err := json.Marshal(result)
		require.NoError(t, err)
		assert.NotContains(t, string(printed), "s3cret")
		assert.NotContains(t, string(printed), testToken)
	})
}

func TestPrecheck_InvalidRepository(t *testing.T) {
	result := Precheck(context.Background(), config.DBSource{Repository: "no-tag/trivy-db"}, testConfig)

	assert.False(t, result.OK)
	assert.Equal(t, []string{"config"}, stageNames(result))
}

func TestParseRepository(t *testing.T) {
	testCases := []struct {
		repository    string
		expected      repositoryRef
		expectedError bool
	}{
		{
			repository: "ghcr.io/aquasecurity/trivy-db:2",
			expected:   repositoryRef{Host: "ghcr.io", Addr: "ghcr.io:443", Path: "aquasecurity/trivy-db", Tag: "2"},
		},
		{
			repository: "docker.io/aquasec/trivy-db:2",
			expected:   repositoryRef{Host: "registry-1.docker.io", Addr: "registry-1.docker.io:443", Path: "aquasec/trivy-db", Tag: "2"},
		},
		{
			repository: "mirror.local:5000/aquasec/trivy-db:2",
			expected:   repositoryRef{Host: "mirror.local:5000", Addr: "mirror.local:5000", Path: "aquasec/trivy-db", Tag: "2"},
		},
		{repository: "ghcr.io/aquasecurity/trivy-db", expectedError: true},
		{repository: "ghcr.io/aquasecurity/trivy-db:", expectedError: true},
		{repository: "mirror.local:5000/aquasec/trivy-db", expectedError: true},
		{repository: "trivy-db:2", expectedError: true},
		{repository: "/trivy-db:2", expectedError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.repository, func(t *testing.T) {
			ref, err := parseRepository(tc.repository)
			if tc.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, ref)
		})
	}
}

func TestGetToken_InvalidRealm(t *testing.T) {
	for _, challenge := range []string{
		`Bearer service="fake"`,
		`Bearer realm="http://insecure.local/token"`,
		`Bearer realm="::bad"`,
	} {
		_, err := getToken(context.Background(), http.DefaultClient, challenge)
		assert.EqualError(t, err, "token: invalid realm in registry challenge", challenge)
	}
}
