package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
)

// fakeResolver answers every tag with err, or with a digest.
type fakeResolver struct {
	err   error
	calls int
}

func (f *fakeResolver) Resolve(ctx context.Context, image registry.Image) (registry.Resolved, error) {
	f.calls++
	if f.err != nil {
		return registry.Resolved{}, f.err
	}
	return registry.Resolved{Digest: "sha256:abc", Reference: "harbor.local/" + image.Repository + "/" + image.Name + "@sha256:abc"}, nil
}

// readiness switches for the handler; all true by default.
type readiness struct {
	storeUp, storeReady, dbInstalled bool
}

func newTestHandler(resolver Resolver, ready readiness) *Handler {
	cfg := config.Config{AuthToken: testToken, MaxInflight: 4, DBMaxAgeDefault: 6 * time.Hour,
		RegistryTimeout: time.Second, MongoOperationTimeout: time.Second}
	return NewHandler(cfg, Deps{
		Registry:     resolver,
		DBState:      dbmgr.NewMemoryStateStore(),
		StoreUp:      func() bool { return ready.storeUp },
		StoreReady:   func() bool { return ready.storeReady },
		DBInstalled:  func() bool { return ready.dbInstalled },
		TrivyVersion: func() string { return "0.74.0" },
	})
}

const validBody = `{"image":{"repository":"customer-1","name":"app","tag":"v1"},"customer_ids":["c1"],"platforms":["npm"]}`

func postScan(h *Handler, body string) *httptest.ResponseRecorder {
	return serve(h, request(http.MethodPost, "/api/v2/scans", testToken, body))
}

func TestCreateScan_BeforeTheStore(t *testing.T) {
	allReady := readiness{storeUp: true, storeReady: true, dbInstalled: true}

	t.Run("validation errors are 400 and come before readiness", func(t *testing.T) {
		resolver := &fakeResolver{}
		h := newTestHandler(resolver, readiness{})
		for name, body := range map[string]string{
			"unknown field":    `{"image":{"repository":"customer-1","name":"app","tag":"v1"},"customer_ids":["c1"],"platforms":["npm"],"priority":1}`,
			"no platforms":     `{"image":{"repository":"customer-1","name":"app","tag":"v1"},"customer_ids":["c1"]}`,
			"bad tag":          `{"image":{"repository":"customer-1","name":"app","tag":"../x"},"customer_ids":["c1"],"platforms":["npm"]}`,
			"customer_data []": `{"image":{"repository":"customer-1","name":"app","tag":"v1"},"customer_ids":["c1"],"platforms":["npm"],"customer_data":[]}`,
		} {
			w := postScan(h, body)
			assert.Equal(t, http.StatusBadRequest, w.Code, name)
			assert.Equal(t, CodeInvalidRequest, errorCode(t, w), name)
		}
		assert.Zero(t, resolver.calls)
	})

	t.Run("not ready is 503 before any registry call", func(t *testing.T) {
		for name, tc := range map[string]struct {
			ready readiness
			code  string
		}{
			"MongoDB down":     {readiness{}, CodeStoreUnavailable},
			"schema not ready": {readiness{storeUp: true}, CodeNotReady},
			"no DB installed":  {readiness{storeUp: true, storeReady: true}, CodeNotReady},
		} {
			resolver := &fakeResolver{}
			w := postScan(newTestHandler(resolver, tc.ready), validBody)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, name)
			assert.Equal(t, tc.code, errorCode(t, w), name)
			assert.NotEmpty(t, w.Header().Get("Retry-After"), name)
			assert.Zero(t, resolver.calls, name)
		}
	})

	t.Run("shutting down is 503 not_ready", func(t *testing.T) {
		h := newTestHandler(&fakeResolver{}, allReady)
		h.StopAccepting()
		w := postScan(h, validBody)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, CodeNotReady, errorCode(t, w))
	})

	t.Run("registry errors are mapped", func(t *testing.T) {
		for name, tc := range map[string]struct {
			err        error
			status     int
			code       string
			retryAfter bool
		}{
			"not found":   {fmt.Errorf("HEAD manifest: %w", registry.ErrImageNotFound), http.StatusNotFound, CodeImageNotFound, false},
			"auth failed": {fmt.Errorf("token: %w", registry.ErrAuthFailed), http.StatusBadGateway, CodeRegistryAuthFailed, false},
			"unavailable": {fmt.Errorf("timeout: %w", registry.ErrUnavailable), http.StatusServiceUnavailable, CodeRegistryUnavailable, true},
			"other":       {fmt.Errorf("status 418 from /home/scanner/x"), http.StatusInternalServerError, CodeInternal, false},
		} {
			w := postScan(newTestHandler(&fakeResolver{err: tc.err}, allReady), validBody)
			assert.Equal(t, tc.status, w.Code, name)
			assert.Equal(t, tc.code, errorCode(t, w), name)
			assert.Equal(t, tc.retryAfter, w.Header().Get("Retry-After") != "", name)
			assert.NotContains(t, w.Body.String(), "/home/scanner", "no paths in messages")
			assert.False(t, strings.Contains(w.Body.String(), "HEAD manifest"), "no internal detail")
		}
	})
}
