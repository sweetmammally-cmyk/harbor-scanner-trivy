package registry

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var image = Image{Repository: "project", Name: "app", Tag: "v1"}

func TestResolve_Errors(t *testing.T) {
	t.Run("unknown tag is image_not_found, not retried", func(t *testing.T) {
		f := startFakeHarbor(t)
		client := newTestClient(t, f, f.config())

		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrImageNotFound)
		assert.Equal(t, int32(2), f.requests.Load(), "the 401 challenge and the 404, nothing more")
	})

	t.Run("refused robot credentials are registry_auth_failed, not retried", func(t *testing.T) {
		f := startFakeHarbor(t)
		cfg := f.config()
		cfg.RegistryPassword = "wr0ng"
		client := newTestClient(t, f, cfg)

		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrAuthFailed)
		assert.Equal(t, int32(1), f.requests.Load())
		assert.Equal(t, int32(1), f.tokenRequests.Load())
	})

	t.Run("403 is registry_auth_failed, not retried", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.handle = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }
		client := newTestClient(t, f, f.config())

		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrAuthFailed)
		assert.Equal(t, int32(1), f.requests.Load())
	})

	t.Run("5xx twice is registry_unavailable after one retry", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.handle = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }
		client := newTestClient(t, f, f.config())

		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrUnavailable)
		assert.Contains(t, err.Error(), "returned status 500")
		assert.Equal(t, int32(2), f.requests.Load())
	})

	t.Run("a 5xx followed by success resolves", func(t *testing.T) {
		f := startFakeHarbor(t)
		var calls atomic.Int32
		f.handle = func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.Header().Set("Docker-Content-Digest", digestOf("m"))
			w.Header().Set("Content-Type", ociManifest)
		}
		client := newTestClient(t, f, f.config())

		resolved, err := client.Resolve(context.Background(), image)

		require.NoError(t, err)
		assert.Equal(t, digestOf("m"), resolved.Digest)
	})

	t.Run("a registry that does not answer times out: registry_unavailable", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.handle = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
		cfg := f.config()
		cfg.RegistryTimeout = 100 * time.Millisecond
		client := newTestClient(t, f, cfg)

		start := time.Now()
		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrUnavailable)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, int32(2), f.requests.Load(), "the timeout is retried once")
		assert.Less(t, time.Since(start), 2*time.Second)
	})

	t.Run("a registry that is down is registry_unavailable", func(t *testing.T) {
		f := startFakeHarbor(t)
		client := newTestClient(t, f, f.config())
		f.server.Close()

		_, err := client.Resolve(context.Background(), image)

		assert.ErrorIs(t, err, ErrUnavailable)
	})

	t.Run("an unexpected status is a plain error", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.handle = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }
		client := newTestClient(t, f, f.config())

		_, err := client.Resolve(context.Background(), image)

		require.Error(t, err)
		assert.EqualError(t, err, "HEAD manifest project/app:v1 returned unexpected status 400")
		assert.Equal(t, int32(1), f.requests.Load())
	})

	t.Run("a caller that gives up gets no retry", func(t *testing.T) {
		f := startFakeHarbor(t)
		f.handle = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
		client := newTestClient(t, f, f.config())
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := client.Resolve(ctx, image)

		assert.ErrorIs(t, err, ErrUnavailable)
		assert.Equal(t, int32(1), f.requests.Load())
	})
}
