package dbmgr

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckUpstream(t *testing.T) {
	f := startFakeOCIRegistry(t, []byte("db layer"))
	client, err := newRegistryClient(f.source(t, "direct"))
	require.NoError(t, err)

	t.Run("same digest is unchanged", func(t *testing.T) {
		manifest, digest, changed, err := checkUpstream(testContext(t), client, f.manifestDigest)

		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, f.manifestDigest, digest)
		assert.Equal(t, f.layerDigest, manifest.Layers[0].Digest)
	})

	t.Run("different digest is changed", func(t *testing.T) {
		old := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		_, digest, changed, err := checkUpstream(testContext(t), client, old)

		require.NoError(t, err)
		assert.True(t, changed)
		assert.Equal(t, f.manifestDigest, digest)
	})

	t.Run("no installed digest is changed", func(t *testing.T) {
		_, _, changed, err := checkUpstream(testContext(t), client, "")

		require.NoError(t, err)
		assert.True(t, changed)
	})

	t.Run("registry error", func(t *testing.T) {
		source := f.source(t, "direct")
		source.Repository = strings.Replace(source.Repository, ":2", ":9", 1)
		missing, err := newRegistryClient(source)
		require.NoError(t, err)

		_, _, changed, err := checkUpstream(testContext(t), missing, f.manifestDigest)

		assert.EqualError(t, err, "upstream check: GET manifest aquasec/trivy-db:9 returned status 404")
		assert.False(t, changed)
	})
}

// makeLayer builds a tar.gz layer with the given files (name, content pairs).
func makeLayer(t *testing.T, files ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	archive := tar.NewWriter(gz)
	for i := 0; i < len(files); i += 2 {
		require.NoError(t, archive.WriteHeader(&tar.Header{
			Name: files[i], Mode: 0o644, Size: int64(len(files[i+1])), Typeflag: tar.TypeReg,
		}))
		_, err := archive.Write([]byte(files[i+1]))
		require.NoError(t, err)
	}
	require.NoError(t, archive.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// serveBlob replaces how the fake registry answers blob requests.
func serveBlob(f *fakeOCIRegistry, handler http.HandlerFunc) {
	next := f.registry.Config.Handler
	f.registry.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/blobs/") {
			handler(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var dbFiles = []string{"trivy.db", "metadata.json"}

func TestDownloadDB(t *testing.T) {
	layer := makeLayer(t,
		"trivy.db", strings.Repeat("bolt db bytes ", 5000),
		"metadata.json", `{"Version":2}`,
		"README", "not wanted",
		"../evil", "must not be written",
	)

	newClient := func(t *testing.T, f *fakeOCIRegistry) *registryClient {
		client, err := newRegistryClient(f.source(t, "direct"))
		require.NoError(t, err)
		return client
	}
	layerOf := func(f *fakeOCIRegistry) ociDescriptor {
		return ociDescriptor{MediaType: trivyDB.MediaType, Digest: f.layerDigest, Size: int64(len(f.layer))}
	}

	t.Run("success extracts only the wanted files", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		f.requireToken = true
		f.redirectBlobs = true
		dest := t.TempDir()

		err := downloadDB(testContext(t), newClient(t, f), layerOf(f), dest, time.Second, dbFiles)

		require.NoError(t, err)
		db, err := os.ReadFile(filepath.Join(dest, "trivy.db"))
		require.NoError(t, err)
		assert.Equal(t, strings.Repeat("bolt db bytes ", 5000), string(db))
		metadata, err := os.ReadFile(filepath.Join(dest, "metadata.json"))
		require.NoError(t, err)
		assert.Equal(t, `{"Version":2}`, string(metadata))

		entries, err := os.ReadDir(dest)
		require.NoError(t, err)
		assert.Len(t, entries, 2)
		assert.NoFileExists(t, filepath.Join(filepath.Dir(dest), "evil"))
	})

	t.Run("wrong digest", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		other := makeLayer(t, "trivy.db", "other db", "metadata.json", "{}")
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(other) })
		descriptor := ociDescriptor{Digest: f.layerDigest, Size: int64(len(other))}

		err := downloadDB(testContext(t), newClient(t, f), descriptor, t.TempDir(), time.Second, dbFiles)

		require.Error(t, err)
		assert.Equal(t, "DB layer digest is "+digestOf(other)+", expected "+f.layerDigest, err.Error())
	})

	t.Run("truncated layer", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(layer[:len(layer)/2]) })

		err := downloadDB(testContext(t), newClient(t, f), layerOf(f), t.TempDir(), time.Second, dbFiles)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected EOF")
	})

	t.Run("layer larger than the manifest says", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(append(append([]byte{}, layer...), "extra"...))
		})

		err := downloadDB(testContext(t), newClient(t, f), layerOf(f), t.TempDir(), time.Second, dbFiles)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "DB layer size is")
	})

	t.Run("missing metadata.json", func(t *testing.T) {
		f := startFakeOCIRegistry(t, makeLayer(t, "trivy.db", "db"))

		err := downloadDB(testContext(t), newClient(t, f), layerOf(f), t.TempDir(), time.Second, dbFiles)

		assert.EqualError(t, err, "DB layer has no metadata.json")
	})

	t.Run("hang in the middle of the download stops at the stall timeout", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(layer[:len(layer)/2])
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})

		start := time.Now()
		err := downloadDB(testContext(t), newClient(t, f), layerOf(f), t.TempDir(), 100*time.Millisecond, dbFiles)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "download stalled: no data for 100ms")
		assert.Less(t, time.Since(start), 2*time.Second)
	})

	t.Run("slow but steady download stops at the overall limit", func(t *testing.T) {
		f := startFakeOCIRegistry(t, layer)
		serveBlob(f, func(w http.ResponseWriter, r *http.Request) {
			for _, b := range layer {
				if _, err := w.Write([]byte{b}); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		})

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		start := time.Now()
		err := downloadDB(ctx, newClient(t, f), layerOf(f), t.TempDir(), time.Second, dbFiles)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "download exceeded the overall limit")
		assert.Less(t, time.Since(start), 2*time.Second)
	})
}
