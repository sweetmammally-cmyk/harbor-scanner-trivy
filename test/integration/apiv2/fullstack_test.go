//go:build integration

package apiv2

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/service"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/mongotest"
)

// stackTrivy is a fake trivy: it records each run, waits while the block file
// exists, fails in "fail" mode, otherwise writes the fixture (real Trivy 0.74.0
// output with alpine, node-pkg and pip results).
const stackTrivy = `#!/bin/sh
if [ "$1" = "--version" ]; then printf 'Version: 0.74.0\n'; exit 0; fi
out=""
prev=""
for a in "$@"; do
  [ "$prev" = "--output" ] && out="$a"
  prev="$a"
done
echo run >> "$TRIVY_FAKE_RUNS"
while [ -e "$TRIVY_FAKE_BLOCK" ]; do sleep 0.05; done
[ "$(cat "$TRIVY_FAKE_MODE_FILE" 2>/dev/null)" = "fail" ] && { echo "FATAL boom at /home/scanner/x" >&2; exit 2; }
cat "$TRIVY_FAKE_FIXTURE" > "$out"
`

const registryPassword = "registry-s3cret-value"

// stack is the whole v2 service: MongoDB, a fake registry, a fake trivy and a
// seed DB, started with service.Start.
type stack struct {
	service  *service.Service
	check    *store.Client
	dir      string
	digests  map[string]string
	mu       sync.Mutex
	stopOnce sync.Once
}

func startStack(t *testing.T, change func(cfg *config.Config)) *stack {
	s := &stack{dir: t.TempDir(), digests: map[string]string{}}

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/manifests/")
		s.mu.Lock()
		digest, found := s.digests[parts[len(parts)-1]]
		s.mu.Unlock()
		if len(parts) != 2 || !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	}))
	t.Cleanup(registry.Close)

	trivy := filepath.Join(s.dir, "trivy")
	require.NoError(t, os.WriteFile(trivy, []byte(stackTrivy), 0o755))
	fixture, err := filepath.Abs("../../../pkg/v2/runner/testdata/node-alpine.json")
	require.NoError(t, err)
	t.Setenv("TRIVY_FAKE_FIXTURE", fixture)
	t.Setenv("TRIVY_FAKE_RUNS", filepath.Join(s.dir, "runs"))
	t.Setenv("TRIVY_FAKE_BLOCK", filepath.Join(s.dir, "block"))
	t.Setenv("TRIVY_FAKE_MODE_FILE", filepath.Join(s.dir, "mode"))

	seed := filepath.Join(s.dir, "seed")
	require.NoError(t, os.MkdirAll(seed, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seed, "trivy.db"), []byte("seed"), 0o644))
	updated := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano) // nanoseconds, like real DBs
	require.NoError(t, os.WriteFile(filepath.Join(seed, "metadata.json"),
		[]byte(`{"Version":2,"UpdatedAt":"`+updated+`","NextUpdate":"`+updated+`","DownloadedAt":"`+updated+`"}`), 0o644))

	cfg := mongotest.Config(mongoAddr)
	cfg.Enabled = true
	cfg.AuthToken = token
	cfg.MaxInflight = 32
	cfg.CacheDir = filepath.Join(s.dir, "cache")
	cfg.InstanceID = "scanner-stack"
	cfg.RegistryURL = registry.URL
	cfg.RegistryUsername = "robot$scanner"
	cfg.RegistryPassword = registryPassword
	cfg.RegistryTimeout = 5 * time.Second
	cfg.DBSeedDir = seed
	cfg.DBSources = []config.DBSource{{Repository: "127.0.0.1:1/aquasec/trivy-db:2"}}
	cfg.DBCheckInterval = time.Hour
	cfg.DBRetryInterval = time.Hour
	cfg.DBAgeWarn = 7 * 24 * time.Hour
	cfg.DBMaxAgeDefault = 6 * time.Hour
	cfg.OnDemandRefreshWait = time.Second
	cfg.OnDemandRefreshMinGap = time.Hour
	cfg.PrecheckTimeoutDNS = time.Second
	cfg.PrecheckTimeoutConnect = time.Second
	cfg.PrecheckTimeoutTLS = time.Second
	cfg.PrecheckTimeoutHTTP = time.Second
	cfg.PrecheckTimeoutManifest = time.Second
	cfg.PrecheckTimeoutTotal = 2 * time.Second
	cfg.QueueWorkers = 1
	cfg.QueueMaxLength = 100
	cfg.QueueLease = time.Minute
	cfg.QueueMaxAttempts = 3
	cfg.QueuePollInterval = 50 * time.Millisecond
	cfg.ShutdownGrace = time.Second
	cfg.ScanTimeout = 30 * time.Second
	cfg.ScanPlatform = "linux/amd64"
	cfg.ScanMaxOutput = 1 << 20
	cfg.ScanMaxFindings = 1000
	if change != nil {
		change(&cfg)
	}

	s.service, err = service.Start(cfg, trivy)
	require.NoError(t, err)
	t.Cleanup(s.stop)
	s.check = mongotest.Client(t, cfg)
	return s
}

func (s *stack) stop() {
	s.stopOnce.Do(func() {
		s.service.StopAccepting()
		s.service.Stop()
	})
}

func (s *stack) setDigest(tag, digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.digests[tag] = digest
}

func (s *stack) do(method, path, requestBody string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(requestBody))
	r.Header.Set("Authorization", "Bearer "+token)
	if requestBody != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.service.Handler().ServeHTTP(w, r)
	return w
}

// runs is how many times trivy scanned.
func (s *stack) runs() int {
	data, _ := os.ReadFile(filepath.Join(s.dir, "runs"))
	return strings.Count(string(data), "run")
}

func (s *stack) state(t *testing.T, id string) string {
	w := s.do(http.MethodGet, "/api/v2/scans/"+id, "")
	var response map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response), w.Body.String())
	state, _ := response["state"].(string)
	return state
}

// postReady posts until the service is ready (MongoDB up, schema, seed DB).
func (s *stack) postReady(t *testing.T, requestBody string) *httptest.ResponseRecorder {
	var w *httptest.ResponseRecorder
	require.Eventually(t, func() bool {
		w = s.do(http.MethodPost, "/api/v2/scans", requestBody)
		return w.Code != http.StatusServiceUnavailable
	}, 20*time.Second, 50*time.Millisecond)
	return w
}

func (s *stack) waitState(t *testing.T, id, state string) {
	require.Eventually(t, func() bool { return s.state(t, id) == state }, 20*time.Second, 20*time.Millisecond, "waiting for %s", state)
}

func TestFullStack(t *testing.T) {
	t.Run("POST -> queued -> scanning -> done; hits, force, copies, narrower and broader requests", func(t *testing.T) {
		s := startStack(t, nil)
		s.setDigest("v1", "sha256:1111")
		s.setDigest("v2", "sha256:1111")
		require.NoError(t, os.WriteFile(filepath.Join(s.dir, "block"), nil, 0o644))

		w := s.postReady(t, body("v1", `"alpine","pip"`, `"severity":["HIGH","CRITICAL","MEDIUM"]`))
		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		id := scanID("v1")
		s.waitState(t, id, "scanning")

		w = s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, ""))
		assert.Equal(t, http.StatusOK, w.Code, "covered by the running scan")
		w = s.do(http.MethodPost, "/api/v2/scans", body("v1", `"npm"`, ""))
		assert.Equal(t, http.StatusConflict, w.Code, "not covered")

		require.NoError(t, os.Remove(filepath.Join(s.dir, "block")))
		s.waitState(t, id, "done")
		assert.Equal(t, 1, s.runs())
		done := decode(t, s.do(http.MethodGet, "/api/v2/scans/"+id, ""))
		timing := done["timing"].(map[string]any)
		assert.Greater(t, timing["total_ms"], 0.0, "timings are recorded")
		assert.Greater(t, timing["scan_ms"], 0.0)
		assert.Contains(t, timing, "queue_wait_ms")
		assert.Equal(t, "sha256:1111", done["image"].(map[string]any)["digest"])

		// The same digest with the same DB: a hit, Trivy does not run.
		before, err := store.NewMongoScans(s.check).Get(context.Background(), id)
		require.NoError(t, err)
		w = s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, `"severity":["CRITICAL"]`))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		hit := decode(t, w)
		assert.Equal(t, true, hit["cached"])
		assert.Equal(t, 1.0, hit["summary"].(map[string]any)["critical"], "narrower request from a wider result")
		for _, v := range hit["vulnerabilities"].([]any) {
			assert.Equal(t, "CRITICAL", v.(map[string]any)["severity"])
		}
		after, err := store.NewMongoScans(s.check).Get(context.Background(), id)
		require.NoError(t, err)
		assert.True(t, after.ConfirmedAt.After(*before.ConfirmedAt))
		assert.Equal(t, 1, s.runs(), "no Trivy process for a hit")

		// A new tag with the same digest: a copy, Trivy does not run.
		w = s.do(http.MethodPost, "/api/v2/scans", body("v2", `"pip"`, ""))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, true, decode(t, w)["cached"])
		assert.Equal(t, 1, s.runs())

		// A scrape of /metrics: the expected names, no forbidden label values,
		// nothing secret.
		scrape := httptest.NewRecorder()
		promhttp.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		text := scrape.Body.String()
		for _, name := range []string{
			`scanner_v2_scans_total{result="done"}`, `scanner_v2_scans_total{result="hit"}`, `scanner_v2_scans_total{result="copy_hit"}`,
			"scanner_v2_scan_duration_seconds_bucket", "scanner_v2_queue_wait_seconds_bucket",
			`scanner_v2_api_requests_total{route="/api/v2/scans",status="200"}`, `route="/api/v2/scans/{id}"`,
			"scanner_v2_api_inflight_requests", "scanner_v2_queue_claims_total", "scanner_v2_queue_claim_seconds_total",
			"scanner_v2_queue_lease_losses_total", "scanner_v2_queue_reaper_requeues_total", "scanner_v2_mongo_up 1",
			`scanner_v2_db_age_seconds{db="db"}`, `scanner_v2_db_confirmed_age_seconds{db="db"}`, `scanner_v2_db_degraded{db="db"} 1`,
			`scanner_v2_db_newer_available{db="db"}`, `scanner_v2_db_update_runs_total{db="db",mode="degraded"}`,
			`scanner_v2_db_precheck_failures_total{class=`, `source="127.0.0.1:1"`,
			`scanner_v2_build_info{schema_version="4",trivy_version="0.74.0"} 1`,
		} {
			assert.Contains(t, text, name)
		}
		for _, forbidden := range []string{"sha256:", "cust-", "project", `"v1"`, `"v2"`, registryPassword, token, "/home/scanner"} {
			assert.NotContains(t, text, forbidden)
		}

		// force and a broader severity scan again.
		w = s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, `"force":true`))
		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		s.waitState(t, id, "done")
		assert.Equal(t, 2, s.runs())
		w = s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, `"severity":["LOW"]`))
		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		s.waitState(t, id, "done")
		assert.Equal(t, 3, s.runs())
	})

	t.Run("concurrent POSTs for one tag run one scan; queue full is 429", func(t *testing.T) {
		s := startStack(t, func(cfg *config.Config) { cfg.QueueMaxLength = 1 })
		s.setDigest("v1", "sha256:1111")
		s.setDigest("v2", "sha256:2222")
		s.setDigest("v3", "sha256:3333")
		require.NoError(t, os.WriteFile(filepath.Join(s.dir, "block"), nil, 0o644))
		require.Equal(t, http.StatusAccepted, s.postReady(t, body("v1", `"alpine"`, "")).Code)
		s.waitState(t, scanID("v1"), "scanning")

		var wg sync.WaitGroup
		codes := make([]int, 8)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = s.do(http.MethodPost, "/api/v2/scans", body("v2", `"alpine"`, "")).Code
			}()
		}
		wg.Wait()
		accepted := 0
		for _, code := range codes {
			if code == http.StatusAccepted {
				accepted++
			}
		}
		assert.Equal(t, 1, accepted, "%v", codes)

		w := s.do(http.MethodPost, "/api/v2/scans", body("v3", `"alpine"`, ""))
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		require.NoError(t, os.Remove(filepath.Join(s.dir, "block")))
		s.waitState(t, scanID("v2"), "done")
		assert.Equal(t, 2, s.runs(), "one scan per tag")
	})

	t.Run("a failed rescan shows the previous result", func(t *testing.T) {
		s := startStack(t, nil)
		s.setDigest("v1", "sha256:1111")
		require.Equal(t, http.StatusAccepted, s.postReady(t, body("v1", `"alpine"`, "")).Code)
		s.waitState(t, scanID("v1"), "done")
		require.NoError(t, os.WriteFile(filepath.Join(s.dir, "mode"), []byte("fail"), 0o644))

		require.Equal(t, http.StatusAccepted, s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, `"force":true`)).Code)
		s.waitState(t, scanID("v1"), "failed")

		w := s.do(http.MethodGet, "/api/v2/scans/"+scanID("v1"), "")
		response := decode(t, w)
		assert.Equal(t, map[string]any{"class": "trivy_exit_error", "message": "Trivy could not scan the image"}, response["error"])
		assert.Equal(t, "sha256:1111", response["previous"].(map[string]any)["digest"])
		assert.NotContains(t, w.Body.String(), "/home/scanner")

		w = s.do(http.MethodGet, "/api/v2/health", "")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		health := decode(t, w)
		assert.Equal(t, "degraded", health["status"], "the DB source is unreachable: degraded mode")
		assert.Equal(t, map[string]any{"window": 20.0, "done": 1.0, "failed": 1.0}, health["recent_scans"])
		assert.Equal(t, 1.0, health["queue"].(map[string]any)["workers"])
		assert.NotContains(t, w.Body.String(), registryPassword)
		assert.NotContains(t, w.Body.String(), "/home/scanner")
	})

	t.Run("not ready without a DB", func(t *testing.T) {
		s := startStack(t, func(cfg *config.Config) { cfg.DBSeedDir = filepath.Join(cfg.CacheDir, "no-seed") })
		s.setDigest("v1", "sha256:1111")
		require.Eventually(t, func() bool {
			w := s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, ""))
			return w.Code == http.StatusServiceUnavailable && errorCode(t, w) == "not_ready"
		}, 20*time.Second, 50*time.Millisecond, "MongoDB comes up, but no DB is installed")
		assert.Equal(t, http.StatusOK, s.do(http.MethodGet, "/api/v2/db", "").Code)
	})

	t.Run("auth, body and registry errors on the whole stack", func(t *testing.T) {
		s := startStack(t, nil)
		s.setDigest("v1", "sha256:1111")
		require.Equal(t, http.StatusAccepted, s.postReady(t, body("v1", `"alpine"`, "")).Code)

		unauthenticated := httptest.NewRecorder()
		s.service.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v2/scans", nil))
		assert.Equal(t, http.StatusUnauthorized, unauthenticated.Code)
		wrong := httptest.NewRequest(http.MethodGet, "/api/v2/db", nil)
		wrong.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
		unauthenticated = httptest.NewRecorder()
		s.service.Handler().ServeHTTP(unauthenticated, wrong)
		assert.Equal(t, http.StatusUnauthorized, unauthenticated.Code)

		assert.Equal(t, http.StatusBadRequest, s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, `"colour":"red"`)).Code)
		assert.Equal(t, http.StatusRequestEntityTooLarge,
			s.do(http.MethodPost, "/api/v2/scans", body("v1", `"alpine"`, `"customer_data":{"x":"`+strings.Repeat("a", 2<<20)+`"}`)).Code)
		w := s.do(http.MethodPost, "/api/v2/scans", body("missing", `"alpine"`, ""))
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "image_not_found", errorCode(t, w))
	})

	t.Run("graceful shutdown: not ready, drain, then the running scan is released; no secrets in logs", func(t *testing.T) {
		logs := &lockedBuffer{}
		defaultLogger := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
		defer slog.SetDefault(defaultLogger)
		s := startStack(t, nil)
		s.setDigest("v1", "sha256:1111")
		require.NoError(t, os.WriteFile(filepath.Join(s.dir, "block"), nil, 0o644))
		require.Equal(t, http.StatusAccepted, s.postReady(t, body("v1", `"alpine"`, "")).Code)
		s.waitState(t, scanID("v1"), "scanning")
		v1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		ready := func() int {
			w := httptest.NewRecorder()
			s.service.Routes(v1).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/probe/ready", nil))
			return w.Code
		}
		assert.Equal(t, http.StatusOK, ready(), "MongoDB, schema, seed DB and trivy are there; degraded DB mode is fine")

		s.service.StopAccepting()
		assert.Equal(t, http.StatusServiceUnavailable, ready())
		w := s.do(http.MethodPost, "/api/v2/scans", body("v2", `"alpine"`, ""))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, "not_ready", errorCode(t, w))

		start := time.Now()
		s.stop()
		assert.Less(t, time.Since(start), 10*time.Second)
		released, err := store.NewMongoScans(s.check).Get(context.Background(), scanID("v1"))
		require.NoError(t, err)
		assert.Equal(t, store.ScanQueued, released.State, "back in the queue for another replica")
		assert.Zero(t, released.Attempt, "the attempt is not counted")
		assert.Empty(t, released.Worker)

		assert.Contains(t, logs.String(), "scan released at shutdown")
		assert.Contains(t, logs.String(), `"msg":"request"`)
		assert.NotContains(t, logs.String(), registryPassword)
		assert.NotContains(t, logs.String(), token)
	})
}

// lockedBuffer is a log buffer shared by the service goroutines and the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
