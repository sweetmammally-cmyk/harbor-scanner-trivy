package registry

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/oci"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	var logs bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(defaultLogger) })
	return &logs
}

func TestResolve_Tokens(t *testing.T) {
	t.Run("an expired token is fetched again", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.add("v1", fakeManifest{body: "m", mediaType: ociManifest, sendDigest: true})
		f.tokenLifetime = 1 // seconds
		client := newTestClient(t, f, f.config())

		_, err := client.Resolve(context.Background(), image)
		require.NoError(t, err)
		_, err = client.Resolve(context.Background(), image)
		require.NoError(t, err)
		assert.Equal(t, int32(1), f.tokenRequests.Load(), "cached while valid")

		time.Sleep(1100 * time.Millisecond)
		_, err = client.Resolve(context.Background(), image)
		require.NoError(t, err)
		assert.Equal(t, int32(2), f.tokenRequests.Load(), "expired: fetched again")
	})

	t.Run("tokens refused after a Harbor restart are replaced", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.add("v1", fakeManifest{body: "m", mediaType: ociManifest, sendDigest: true})
		client := newTestClient(t, f, f.config())
		_, err := client.Resolve(context.Background(), image)
		require.NoError(t, err)

		f.mu.Lock()
		f.tokens = map[string]bool{}
		f.mu.Unlock()
		_, err = client.Resolve(context.Background(), image)

		require.NoError(t, err)
		assert.Equal(t, int32(2), f.tokenRequests.Load())
	})

	t.Run("an endless chain of challenges stops: registry_auth_failed", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.handle = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="`+f.server.URL+`/service/token",service="harbor-registry",scope="repository:project/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
		client := newTestClient(t, f, f.config())

		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrAuthFailed)
		assert.Equal(t, int32(oci.MaxChallenges+1), f.requests.Load(), "bounded, and a 401 is not retried")
	})
}

func TestResolve_Redirect(t *testing.T) {
	var forwardedAuthorization []string
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedAuthorization = append(forwardedAuthorization, r.Header.Get("Authorization"))
		w.Header().Set("Docker-Content-Digest", digestOf("redirected"))
		w.Header().Set("Content-Type", ociManifest)
	}))
	defer other.Close()

	f := startFakeHarbor(t)
	f.handle = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="`+f.server.URL+`/service/token",service="harbor-registry",scope="repository:project/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, other.URL+"/manifest", http.StatusTemporaryRedirect)
	}
	client := newTestClient(t, f, f.config())
	// One HTTP client that trusts both test certificates.
	httpClient := f.server.Client()
	httpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(other.Certificate())
	client.oci = oci.NewClient(httpClient, oci.Credentials{Username: robotUser, Password: robotPassword})

	resolved, err := client.Resolve(context.Background(), image)

	require.NoError(t, err)
	assert.Equal(t, digestOf("redirected"), resolved.Digest)
	assert.Equal(t, []string{""}, forwardedAuthorization, "the token is not sent to the other host")
}

func TestNewClient_PlainHTTPWarning(t *testing.T) {
	logs := captureLogs(t)

	_, err := NewClient(config.Config{RegistryURL: "http://harbor.local", RegistryUsername: robotUser, RegistryPassword: robotPassword})
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(logs.String(), `"level":"WARN"`))
	assert.Contains(t, logs.String(), `"msg":"SCANNER_REGISTRY_URL uses plain http: registry traffic and the robot credentials are not encrypted","registry":"harbor.local"`)

	logs.Reset()
	_, err = NewClient(config.Config{RegistryURL: "https://harbor.local"})
	require.NoError(t, err)
	assert.Empty(t, logs.String(), "no warning for https")
}

// TestResolve_Redaction goes through every failure mode with credentials set and
// checks that no secret reaches an error or a log line.
func TestResolve_Redaction(t *testing.T) {
	secrets := []string{robotPassword, "wr0ng", "harbor-token-", "Basic ", "Bearer ", "Authorization"}
	handlers := map[string]http.HandlerFunc{
		"500":  func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"403":  func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) },
		"hang": func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
	}
	logs := captureLogs(t)
	var errs []error

	for name, handler := range handlers {
		f := startFakeHarbor(t)
		f.handle = handler
		cfg := f.config()
		cfg.RegistryTimeout = 100 * time.Millisecond
		_, err := newTestClient(t, f, cfg).Resolve(context.Background(), image)
		require.Error(t, err, name)
		errs = append(errs, err)
	}
	f := startFakeHarbor(t)
	cfg := f.config()
	cfg.RegistryPassword = "wr0ng"
	_, err := newTestClient(t, f, cfg).Resolve(context.Background(), image)
	require.ErrorIs(t, err, ErrAuthFailed)
	errs = append(errs, err)

	f = startFakeHarbor(t) // a token was issued, then the tag is missing
	_, err = newTestClient(t, f, f.config()).Resolve(context.Background(), image)
	require.ErrorIs(t, err, ErrImageNotFound)
	errs = append(errs, err)

	for _, err := range errs {
		for _, secret := range secrets {
			assert.NotContains(t, err.Error(), secret)
		}
	}
	for _, secret := range secrets {
		assert.NotContains(t, logs.String(), secret)
	}
}
