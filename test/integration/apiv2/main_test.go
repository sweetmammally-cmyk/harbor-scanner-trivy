//go:build integration

// Package apiv2 tests the /api/v2 handler on a real MongoDB with a fake registry.
package apiv2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/queue"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
	"github.com/aquasecurity/harbor-scanner-trivy/test/integration/mongotest"
)

const token = "0123456789abcdef0123456789abcdef"

var mongoAddr string

func TestMain(m *testing.M) {
	addr, stop, err := mongotest.StartContainer()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	mongoAddr = addr
	code := m.Run()
	stop()
	os.Exit(code)
}

// fakeRegistry resolves each tag to the digest set for it ("sha256:<tag>" by default).
type fakeRegistry struct {
	mu      sync.Mutex
	digests map[string]string
}

func (f *fakeRegistry) set(tag, digest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.digests[tag] = digest
}

func (f *fakeRegistry) Resolve(ctx context.Context, image registry.Image) (registry.Resolved, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	digest, found := f.digests[image.Tag]
	if !found {
		digest = "sha256:" + image.Tag
	}
	return registry.Resolved{Digest: digest, Reference: "harbor.local/" + image.Repository + "/" + image.Name + "@" + digest}, nil
}

// env is one scanner replica's API on a fresh database.
type env struct {
	handler  *api.Handler
	client   *store.Client
	cfg      config.Config
	queue    *queue.Queue
	reports  store.ReportStore
	registry *fakeRegistry
	dbState  *dbmgr.MemoryStateStore
}

func newEnv(t *testing.T, change func(cfg *config.Config)) *env {
	cfg := mongotest.Config(mongoAddr)
	cfg.AuthToken = token
	cfg.MaxInflight = 32
	cfg.QueueMaxLength = 100
	cfg.QueueWorkers = 1
	cfg.QueueLease = time.Minute
	cfg.QueueMaxAttempts = 3
	cfg.QueuePollInterval = 50 * time.Millisecond
	cfg.ShutdownGrace = 5 * time.Second
	cfg.DBMaxAgeDefault = 6 * time.Hour
	cfg.RegistryTimeout = 5 * time.Second
	cfg.ScanPlatform = "linux/amd64"
	if change != nil {
		change(&cfg)
	}
	client := mongotest.Client(t, cfg)
	return newReplica(t, cfg, client)
}

// newReplica is another replica on the same database as e.
func (e *env) newReplica(t *testing.T) *env {
	replica := newReplica(t, e.cfg, mongotest.Client(t, e.cfg))
	replica.registry = e.registry
	return replica
}

func newReplica(t *testing.T, cfg config.Config, client *store.Client) *env {
	e := &env{client: client, cfg: cfg, registry: &fakeRegistry{digests: map[string]string{}}, dbState: dbmgr.NewMemoryStateStore()}
	e.queue = queue.New(client, cfg)
	e.reports = store.NewMongoReports(client, store.ReportInlineLimit)
	installed := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	require.NoError(t, e.dbState.Save(context.Background(), "db", dbmgr.DBState{
		Mode: dbmgr.ModeNormal, LastUpstreamCheckAt: installed, LastConfirmedCurrentAt: installed,
		Metadata: dbmgr.Metadata{Version: 2, UpdatedAt: installed.Add(-time.Hour)},
	}))
	e.handler = api.NewHandler(cfg, api.Deps{
		Queue:        e.queue,
		Scans:        store.NewMongoScans(client),
		Reports:      e.reports,
		Registry:     e.registry,
		DBState:      e.dbState,
		StoreUp:      func() bool { return true },
		StoreReady:   func() bool { return true },
		DBInstalled:  func() bool { return true },
		TrivyVersion: func() string { return "0.74.0" },
	})
	return e
}

// body is a scan request for a tag; extra JSON fields are appended.
func body(tag string, platforms string, extra string) string {
	b := `{"image":{"repository":"project","name":"app","tag":"` + tag + `"},"customer_ids":["cust-1"],"platforms":[` + platforms + `]`
	if extra != "" {
		b += "," + extra
	}
	return b + "}"
}

func (e *env) do(method, path, requestBody string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(requestBody))
	r.Header.Set("Authorization", "Bearer "+token)
	if requestBody != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
}

func (e *env) post(requestBody string) *httptest.ResponseRecorder {
	return e.do(http.MethodPost, "/api/v2/scans", requestBody)
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	var v map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &v), w.Body.String())
	return v
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	return decode(t, w)["error"].(map[string]any)["code"].(string)
}

func (e *env) scan(t *testing.T, id string) store.Scan {
	scan, err := store.NewMongoScans(e.client).Get(context.Background(), id)
	require.NoError(t, err)
	return scan
}

func (e *env) count(t *testing.T) int64 {
	ctx, cancel := e.client.OperationContext(context.Background())
	defer cancel()
	count, err := e.client.Database().Collection(store.CollectionScans).CountDocuments(ctx, bson.M{})
	require.NoError(t, err)
	return count
}

func scanID(tag string) string {
	return store.ScanID(store.Image{Repository: "project", Name: "app", Tag: tag})
}
