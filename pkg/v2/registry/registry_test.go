package registry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/oci"
)

const (
	robotUser     = "robot$scanner"
	robotPassword = "s3cret-robot"
	ociManifest   = "application/vnd.oci.image.manifest.v1+json"
	ociIndex      = "application/vnd.oci.image.index.v1+json"
)

// fakeHarbor serves manifests of project/app behind Harbor's token service,
// which only gives tokens to the robot account.
type fakeHarbor struct {
	server *httptest.Server

	mu        sync.Mutex
	manifests map[string]fakeManifest // by tag
	tokens    map[string]bool
	// handle, when set, answers manifest requests instead of the normal logic.
	handle http.HandlerFunc
	// tokenLifetime is the expires_in of issued tokens, in seconds (1800 when 0).
	tokenLifetime int

	requests      atomic.Int32
	tokenRequests atomic.Int32
}

type fakeManifest struct {
	body       string
	mediaType  string
	sendDigest bool
}

func startFakeHarbor(t *testing.T) *fakeHarbor {
	f := &fakeHarbor{manifests: map[string]fakeManifest{}, tokens: map[string]bool{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeHarbor) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/service/token" {
		f.tokenRequests.Add(1)
		wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(robotUser+":"+robotPassword))
		if r.Header.Get("Authorization") != wantBasic {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := fmt.Sprintf("harbor-token-%d", f.tokenRequests.Load())
		f.mu.Lock()
		f.tokens[token] = true
		lifetime := f.tokenLifetime
		f.mu.Unlock()
		if lifetime == 0 {
			lifetime = 1800
		}
		_, _ = fmt.Fprintf(w, `{"token":%q,"expires_in":%d}`, token, lifetime)
		return
	}

	f.requests.Add(1)
	f.mu.Lock()
	handle := f.handle
	authorized := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	f.mu.Unlock()
	if handle != nil {
		handle(w, r)
		return
	}
	if !authorized {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="`+f.server.URL+`/service/token",service="harbor-registry",scope="repository:project/app:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tag := strings.TrimPrefix(r.URL.Path, "/v2/project/app/manifests/")
	f.mu.Lock()
	manifest, found := f.manifests[tag]
	f.mu.Unlock()
	if !found || !strings.HasPrefix(r.URL.Path, "/v2/project/app/manifests/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", manifest.mediaType+"; charset=utf-8")
	if manifest.sendDigest {
		w.Header().Set("Docker-Content-Digest", digestOf(manifest.body))
	}
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(manifest.body))
	}
}

func (f *fakeHarbor) add(tag string, manifest fakeManifest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[tag] = manifest
}

func digestOf(body string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(body)))
}

func (f *fakeHarbor) config() config.Config {
	return config.Config{
		RegistryURL:      f.server.URL,
		RegistryUsername: robotUser,
		RegistryPassword: robotPassword,
		RegistryTimeout:  2 * time.Second,
	}
}

// newTestClient returns a client of the fake Harbor that trusts its certificate.
func newTestClient(t *testing.T, f *fakeHarbor, cfg config.Config) *Client {
	t.Helper()
	client, err := NewClient(cfg)
	require.NoError(t, err)
	client.oci = oci.NewClient(f.server.Client(), oci.Credentials{Username: cfg.RegistryUsername, Password: cfg.RegistryPassword})
	return client
}

func TestResolve(t *testing.T) {
	f := startFakeHarbor(t)
	f.add("v1", fakeManifest{body: `{"schemaVersion":2,"layers":[]}`, mediaType: ociManifest, sendDigest: true})
	f.add("multi", fakeManifest{body: `{"schemaVersion":2,"manifests":[]}`, mediaType: ociIndex, sendDigest: true})
	f.add("nodigest", fakeManifest{body: `{"schemaVersion":2, "exact": "bytes"}`, mediaType: ociManifest})
	client := newTestClient(t, f, f.config())
	host := strings.TrimPrefix(f.server.URL, "https://")

	t.Run("plain manifest with the robot's token", func(t *testing.T) {
		resolved, err := client.Resolve(context.Background(), Image{Repository: "project", Name: "app", Tag: "v1"})

		require.NoError(t, err)
		assert.Equal(t, digestOf(`{"schemaVersion":2,"layers":[]}`), resolved.Digest)
		assert.Equal(t, ociManifest, resolved.MediaType, "parameters such as charset are dropped")
		assert.Equal(t, host+"/project/app@"+resolved.Digest, resolved.Reference, "scan by digest, never by tag")
	})

	t.Run("image index", func(t *testing.T) {
		resolved, err := client.Resolve(context.Background(), Image{Repository: "project", Name: "app", Tag: "multi"})

		require.NoError(t, err)
		assert.Equal(t, ociIndex, resolved.MediaType)
		assert.Equal(t, digestOf(`{"schemaVersion":2,"manifests":[]}`), resolved.Digest)
	})

	t.Run("no Docker-Content-Digest: GET and hash the exact bytes", func(t *testing.T) {
		resolved, err := client.Resolve(context.Background(), Image{Repository: "project", Name: "app", Tag: "nodigest"})

		require.NoError(t, err)
		assert.Equal(t, digestOf(`{"schemaVersion":2, "exact": "bytes"}`), resolved.Digest)
	})

	t.Run("the token is reused across resolves", func(t *testing.T) {
		assert.Equal(t, int32(1), f.tokenRequests.Load())
	})
}

func TestValidateImage(t *testing.T) {
	valid := []Image{
		{Repository: "project", Name: "app", Tag: "v1.2.0"},
		{Repository: "customer-123", Name: "app", Tag: "latest"},
		{Repository: "a.b_c", Name: "x--y", Tag: "_build.7-rc"},
		{Repository: "group/sub", Name: "app__x", Tag: strings.Repeat("t", 128)},
	}
	for _, image := range valid {
		assert.NoError(t, ValidateImage(image), "%+v", image)
	}

	invalid := []Image{
		{Repository: "Project", Name: "app", Tag: "v1"},
		{Repository: "project", Name: "a..b", Tag: "v1"},
		{Repository: "project", Name: "..", Tag: "v1"},
		{Repository: "..", Name: "app", Tag: "v1"},
		{Repository: "project", Name: "a%2e%2e", Tag: "v1"},
		{Repository: "project", Name: "app", Tag: "v1%2F"},
		{Repository: "project", Name: "", Tag: "v1"},
		{Repository: "project/", Name: "app", Tag: "v1"},
		{Repository: "project", Name: "-app", Tag: "v1"},
		{Repository: "project", Name: "app", Tag: ""},
		{Repository: "project", Name: "app", Tag: ".v1"},
		{Repository: "project", Name: "app", Tag: "-v1"},
		{Repository: "project", Name: "app", Tag: "v1/x"},
		{Repository: "project", Name: "app", Tag: strings.Repeat("t", 129)},
		{Repository: strings.Repeat("a", 200), Name: strings.Repeat("b", 60), Tag: "v1"},
		{Repository: "project", Name: "app", Tag: "v1@sha256:abc"},
	}
	for _, image := range invalid {
		assert.ErrorIs(t, ValidateImage(image), ErrInvalidName, "%+v", image)
	}
}

func TestResolve_InvalidNameMakesNoRequest(t *testing.T) {
	f := startFakeHarbor(t)
	client := newTestClient(t, f, f.config())

	_, err := client.Resolve(context.Background(), Image{Repository: "project", Name: "../admin", Tag: "v1"})

	assert.ErrorIs(t, err, ErrInvalidName)
	assert.Equal(t, int32(0), f.requests.Load())
}

func TestNewClient(t *testing.T) {
	for _, url := range []string{"", "harbor.local", "ftp://harbor.local", "https://"} {
		_, err := NewClient(config.Config{RegistryURL: url})
		assert.EqualError(t, err, "SCANNER_REGISTRY_URL must be http(s)://host[:port]", url)
	}

	client, err := NewClient(config.Config{RegistryURL: "https://harbor.local:8443/some/path"})
	require.NoError(t, err)
	assert.Equal(t, "https://harbor.local:8443", client.base.String(), "only scheme and host are used")
}
