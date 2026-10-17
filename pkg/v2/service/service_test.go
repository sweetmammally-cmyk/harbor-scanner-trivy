package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// TestStartStop: with MongoDB unreachable and Trivy missing the service still
// starts (not ready), serves the API behind the token, and stops promptly.
func TestStartStop(t *testing.T) {
	cfg := config.Config{
		Enabled:                     true,
		AuthToken:                   "0123456789abcdef0123456789abcdef",
		MaxInflight:                 4,
		CacheDir:                    t.TempDir(),
		InstanceID:                  "scanner-test",
		MongoURI:                    "mongodb://127.0.0.1:1/?directConnection=true",
		MongoDB:                     "scanner",
		RegistryURL:                 "https://harbor.local",
		MongoConnectTimeout:         200 * time.Millisecond,
		MongoServerSelectionTimeout: 200 * time.Millisecond,
		MongoOperationTimeout:       time.Second,
		DBCheckInterval:             time.Hour,
		DBRetryInterval:             time.Hour,
		DBSources:                   []config.DBSource{{Repository: "127.0.0.1:1/aquasec/trivy-db:2"}},
		PrecheckTimeoutDNS:          time.Second,
		PrecheckTimeoutConnect:      time.Second,
		PrecheckTimeoutTLS:          time.Second,
		PrecheckTimeoutHTTP:         time.Second,
		PrecheckTimeoutManifest:     time.Second,
		PrecheckTimeoutTotal:        2 * time.Second,
		QueueWorkers:                2,
		QueueLease:                  time.Minute,
		QueuePollInterval:           50 * time.Millisecond,
		ShutdownGrace:               time.Second,
		ScanPlatform:                "linux/amd64",
	}

	s, err := Start(cfg, "/nonexistent/trivy")
	require.NoError(t, err)

	v1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	routes := s.Routes(v1)
	get := func(path string) int {
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w.Code
	}
	assert.Equal(t, http.StatusUnauthorized, get("/api/v2/scans"), "v2 needs the token")
	assert.Equal(t, http.StatusServiceUnavailable, get("/probe/ready"), "MongoDB down, no DB, no trivy: not ready")
	assert.Equal(t, http.StatusTeapot, get("/probe/healthy"), "liveness is v1's, up while MongoDB is down")
	assert.Equal(t, http.StatusTeapot, get("/api/v1/metadata"), "v1 routes are unchanged")

	stopped := make(chan struct{})
	go func() {
		s.StopAccepting()
		s.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		t.Fatal("Stop did not return")
	}
}
