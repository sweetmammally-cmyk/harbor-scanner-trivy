package dbmgr

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// fakeOCIRegistry serves aquasec/trivy-db:2 as an OCI artifact with one layer.
// Blobs can be redirected to a second TLS server, like ghcr.io does with its CDN.
type fakeOCIRegistry struct {
	registry *httptest.Server
	cdn      *httptest.Server

	layer          []byte
	layerDigest    string
	manifest       []byte
	manifestDigest string

	// Changed by tests before requests are made.
	requireToken   bool
	redirectBlobs  bool
	manifestHeader string // overrides Docker-Content-Digest when set

	mu             sync.Mutex
	tokenRequests  int
	cdnAuthHeaders []string
}

func digestOf(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

func startFakeOCIRegistry(t *testing.T, layer []byte) *fakeOCIRegistry {
	t.Helper()
	f := &fakeOCIRegistry{layer: layer, layerDigest: digestOf(layer)}

	manifest, err := json.Marshal(ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Layers:    []ociDescriptor{{MediaType: trivyDB.MediaType, Digest: f.layerDigest, Size: int64(len(layer))}},
	})
	require.NoError(t, err)
	f.manifest = manifest
	f.manifestDigest = digestOf(manifest)

	f.cdn = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.cdnAuthHeaders = append(f.cdnAuthHeaders, r.Header.Get("Authorization"))
		f.mu.Unlock()
		_, _ = w.Write(f.layer)
	}))
	f.cdn.EnableHTTP2 = true
	f.cdn.StartTLS()
	t.Cleanup(f.cdn.Close)

	f.registry = httptest.NewUnstartedServer(http.HandlerFunc(f.serveRegistry))
	f.registry.EnableHTTP2 = true
	f.registry.StartTLS()
	t.Cleanup(f.registry.Close)

	// Add to the pool, so a test can run several fake registries.
	pool := rootCAs
	if pool == nil {
		pool = x509.NewCertPool()
		t.Cleanup(func() { rootCAs = nil })
	}
	pool.AddCert(f.registry.Certificate())
	pool.AddCert(f.cdn.Certificate())
	rootCAs = pool

	return f
}

func (f *fakeOCIRegistry) serveRegistry(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		f.mu.Lock()
		f.tokenRequests++
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"token":"` + testToken + `"}`))
		return
	}

	if f.requireToken && r.Header.Get("Authorization") != "Bearer "+testToken {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="https://`+f.registry.Listener.Addr().String()+`/token",service="fake",scope="repository:aquasec/trivy-db:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch r.URL.Path {
	case "/v2/":
		w.WriteHeader(http.StatusOK)
	case "/v2/aquasec/trivy-db/manifests/2":
		header := f.manifestDigest
		if f.manifestHeader != "" {
			header = f.manifestHeader
		}
		w.Header().Set("Docker-Content-Digest", header)
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write(f.manifest)
	case "/v2/aquasec/trivy-db/blobs/" + f.layerDigest:
		if f.redirectBlobs {
			http.Redirect(w, r, "https://"+f.cdn.Listener.Addr().String()+"/blob-data", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write(f.layer)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOCIRegistry) source(t *testing.T, route string) config.DBSource {
	t.Helper()
	sources, err := config.ParseDBSources(f.registry.Listener.Addr().String() + "/aquasec/trivy-db:2|" + route)
	require.NoError(t, err)
	return sources[0]
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRegistryClient_GetManifest(t *testing.T) {
	f := startFakeOCIRegistry(t, []byte("db layer content"))
	client, err := newRegistryClient(f.source(t, "direct"))
	require.NoError(t, err)

	manifest, digest, err := client.getManifest(testContext(t))

	require.NoError(t, err)
	assert.Equal(t, f.manifestDigest, digest)
	require.Len(t, manifest.Layers, 1)
	assert.Equal(t, trivyDB.MediaType, manifest.Layers[0].MediaType)
	assert.Equal(t, f.layerDigest, manifest.Layers[0].Digest)
	assert.Equal(t, int64(len("db layer content")), manifest.Layers[0].Size)
}

func TestRegistryClient_GetManifestErrors(t *testing.T) {
	t.Run("digest header does not match the content", func(t *testing.T) {
		f := startFakeOCIRegistry(t, []byte("layer"))
		f.manifestHeader = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		client, err := newRegistryClient(f.source(t, "direct"))
		require.NoError(t, err)

		_, _, err = client.getManifest(testContext(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match Docker-Content-Digest")
	})

	t.Run("manifest without layers", func(t *testing.T) {
		f := startFakeOCIRegistry(t, []byte("layer"))
		f.manifest = []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`)
		f.manifestDigest = digestOf(f.manifest)
		client, err := newRegistryClient(f.source(t, "direct"))
		require.NoError(t, err)

		_, _, err = client.getManifest(testContext(t))
		assert.EqualError(t, err, "manifest aquasec/trivy-db:2 has no layers")
	})

	t.Run("unknown tag", func(t *testing.T) {
		f := startFakeOCIRegistry(t, []byte("layer"))
		source := f.source(t, "direct")
		source.Repository = strings.Replace(source.Repository, ":2", ":9", 1)
		client, err := newRegistryClient(source)
		require.NoError(t, err)

		_, _, err = client.getManifest(testContext(t))
		assert.EqualError(t, err, "GET manifest aquasec/trivy-db:9 returned status 404")
	})
}

func TestRegistryClient_GetBlob(t *testing.T) {
	layer := []byte(strings.Repeat("trivy db ", 1000))

	t.Run("token is fetched once and reused for the blob", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		f.requireToken = true
		client, err := newRegistryClient(f.source(t, "direct"))
		require.NoError(t, err)

		manifest, _, err := client.getManifest(testContext(t))
		require.NoError(t, err)
		body, err := client.getBlob(testContext(t), manifest.Layers[0].Digest)
		require.NoError(t, err)
		defer body.Close()
		got, err := io.ReadAll(body)
		require.NoError(t, err)

		assert.Equal(t, layer, got)
		assert.Equal(t, 1, f.tokenRequests)
	})

	t.Run("redirect to a CDN does not send the token there", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		f.requireToken = true
		f.redirectBlobs = true
		client, err := newRegistryClient(f.source(t, "direct"))
		require.NoError(t, err)

		body, err := client.getBlob(testContext(t), f.layerDigest)
		require.NoError(t, err)
		defer body.Close()
		got, err := io.ReadAll(body)
		require.NoError(t, err)

		assert.Equal(t, layer, got)
		assert.Equal(t, []string{""}, f.cdnAuthHeaders, "the CDN must not receive the registry token")
	})

	t.Run("redirect goes through the same proxy", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		f.redirectBlobs = true
		proxy := startSOCKS5Proxy(t, "user", "s3cret")
		client, err := newRegistryClient(f.source(t, "socks5://user:s3cret@"+proxy.addr))
		require.NoError(t, err)

		body, err := client.getBlob(testContext(t), f.layerDigest)
		require.NoError(t, err)
		_, err = io.ReadAll(body)
		require.NoError(t, err)
		require.NoError(t, body.Close())

		assert.Contains(t, proxy.targets(), f.registry.Listener.Addr().String())
		assert.Contains(t, proxy.targets(), f.cdn.Listener.Addr().String())
	})

	t.Run("unknown blob", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		client, err := newRegistryClient(f.source(t, "direct"))
		require.NoError(t, err)

		missing := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		_, err = client.getBlob(testContext(t), missing)
		assert.EqualError(t, err, "GET blob "+missing+" returned status 404")
	})
}

func TestNewRegistryClient_InvalidRepository(t *testing.T) {
	_, err := newRegistryClient(config.DBSource{Repository: "no-tag/trivy-db"})
	assert.Error(t, err)
}
