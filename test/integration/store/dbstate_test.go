//go:build integration

package store

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// storedState reads a db_state document; found is false when there is none.
func storedState(t *testing.T, client *store.Client, id string) (store.DBStateDocument, bool) {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	var document store.DBStateDocument
	err := client.Database().Collection(store.CollectionDBState).FindOne(ctx, bson.M{"_id": id}).Decode(&document)
	if err != nil {
		return store.DBStateDocument{}, false
	}
	return document, true
}

func countChecks(t *testing.T, client *store.Client, instanceID string) int64 {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	count, err := client.Database().Collection(store.CollectionDBChecks).CountDocuments(ctx, bson.M{"instance_id": instanceID})
	require.NoError(t, err)
	return count
}

func stateWithSource(mode, digest string) dbmgr.DBState {
	return dbmgr.DBState{
		Mode:           mode,
		ManifestDigest: digest,
		LastSources: []dbmgr.SourceResult{{
			Source:   "mirror|direct",
			Answered: true,
			Precheck: dbmgr.CheckResult{OK: true, StartedAt: time.Now().UTC().Truncate(time.Millisecond)},
		}},
	}
}

func TestDBStateStore(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}
	mongoAddr := startMongo(t)

	t.Run("two instances write concurrently without overwriting each other", func(t *testing.T) {
		name := fmt.Sprintf("dbstate_%d", databaseCounter.Add(1))
		stores := map[string]*store.DBStateStore{}
		var reader *store.Client
		for _, instance := range []string{"scanner-a", "scanner-b"} {
			client := newClient(t, schemaConfig(mongoAddr, name, 24*time.Hour))
			stores[instance] = store.NewDBStateStore(client, instance)
			monitor(t, client)
			require.Eventually(t, client.Ready, 15*time.Second, 50*time.Millisecond)
			reader = client
		}

		var wg sync.WaitGroup
		for instance, s := range stores {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for run := 1; run <= 10; run++ {
					_ = s.Save(context.Background(), "db", stateWithSource(dbmgr.ModeNormal, fmt.Sprintf("sha256:%s-%d", instance, run)))
				}
			}()
		}
		wg.Wait()

		for _, instance := range []string{"scanner-a", "scanner-b"} {
			document, found := storedState(t, reader, instance+":db")
			require.True(t, found, instance)
			assert.Equal(t, instance, document.InstanceID)
			assert.Equal(t, "db", document.DB)
			assert.Equal(t, "sha256:"+instance+"-10", document.ManifestDigest, "each instance keeps its own last state")
			assert.EqualValues(t, 10, countChecks(t, reader, instance))
		}
	})

	t.Run("state saved while MongoDB was down is written when it comes back, without a new run", func(t *testing.T) {
		name := fmt.Sprintf("dbstate_%d", databaseCounter.Add(1))
		proxy := newForwarder(t, mongoAddr)
		client := newClient(t, schemaConfig(proxy.addr, name, 24*time.Hour))
		s := store.NewDBStateStore(client, "scanner-1")
		monitor(t, client)
		direct := newClient(t, schemaConfig(mongoAddr, name, 24*time.Hour))

		require.NoError(t, s.Save(context.Background(), "db", stateWithSource(dbmgr.ModeDegraded, "sha256:while-down")))
		time.Sleep(500 * time.Millisecond)
		_, found := storedState(t, direct, "scanner-1:db")
		assert.False(t, found, "nothing written while MongoDB is down")

		proxy.start(t)

		require.Eventually(t, func() bool {
			document, found := storedState(t, direct, "scanner-1:db")
			return found && document.ManifestDigest == "sha256:while-down"
		}, 30*time.Second, 100*time.Millisecond)
		require.Eventually(t, func() bool { return countChecks(t, direct, "scanner-1") == 1 }, 10*time.Second, 100*time.Millisecond)
	})

	t.Run("an updater run reaches db_state and db_checks end to end", func(t *testing.T) {
		name := fmt.Sprintf("dbstate_%d", databaseCounter.Add(1))
		client := newClient(t, schemaConfig(mongoAddr, name, 24*time.Hour))
		s := store.NewDBStateStore(client, "scanner-1")
		monitor(t, client)
		require.Eventually(t, client.Ready, 15*time.Second, 50*time.Millisecond)

		// One source whose port is closed: its pre-check fails with tcp_refused.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		closed := listener.Addr().String()
		require.NoError(t, listener.Close())
		sources, err := config.ParseDBSources(closed + "/aquasec/trivy-db:2|direct")
		require.NoError(t, err)
		cfg := mongoConfig(mongoAddr)
		cfg.DBSources = sources
		cfg.PrecheckTimeoutDNS, cfg.PrecheckTimeoutConnect = time.Second, time.Second
		cfg.PrecheckTimeoutTotal = 5 * time.Second

		_, err = dbmgr.NewUpdater(context.Background(), cfg, t.TempDir(), s).UpdateNow(context.Background())
		require.NoError(t, err)

		document, found := storedState(t, client, "scanner-1:db")
		require.True(t, found)
		assert.Equal(t, dbmgr.ModeDegraded, document.Mode)
		require.Len(t, document.LastSources, 1)
		assert.Equal(t, "tcp_refused", document.LastSources[0].FailureClass)

		checks, err := store.NewMongoDBChecks(client).Recent(context.Background(), "db", 10)
		require.NoError(t, err)
		require.Len(t, checks, 1)
		assert.Equal(t, "scanner-1", checks[0].InstanceID)
		assert.Equal(t, "tcp_refused", checks[0].FailureClass)
		assert.Equal(t, "dns", checks[0].Precheck.Stages[0].Stage, "per-stage results are stored")
	})

	t.Run("startup load ignores the stored confirmation when the disk has another DB", func(t *testing.T) {
		name := fmt.Sprintf("dbstate_%d", databaseCounter.Add(1))
		client := newClient(t, schemaConfig(mongoAddr, name, 24*time.Hour))
		require.NoError(t, client.EnsureSchema(context.Background()))
		confirmed := time.Now().UTC().Truncate(time.Millisecond)
		for _, document := range []store.DBStateDocument{
			{ID: "scanner-1:db", InstanceID: "scanner-1", DB: "db", DBState: dbmgr.DBState{
				Mode: dbmgr.ModeNormal, ManifestDigest: "sha256:stored", LastConfirmedCurrentAt: confirmed, NewerAvailable: true}},
			{ID: "scanner-1:java-db", InstanceID: "scanner-1", DB: "java-db", DBState: dbmgr.DBState{
				Mode: dbmgr.ModeNormal, ManifestDigest: "sha256:java", LastConfirmedCurrentAt: confirmed}},
			{ID: "scanner-2:db", InstanceID: "scanner-2", DB: "db", DBState: dbmgr.DBState{Mode: "other instance"}},
		} {
			require.NoError(t, insert(t, client, store.CollectionDBState, document))
		}
		cacheDir := t.TempDir()
		for db, digest := range map[string]string{"db": "sha256:on-disk", "java-db": "sha256:java"} {
			require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, db), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(cacheDir, db, "manifest-digest"), []byte(digest), 0o644))
		}
		s := store.NewDBStateStore(client, "scanner-1")

		require.NoError(t, s.Load(context.Background(), cacheDir))

		state, err := s.Get(context.Background(), "db")
		require.NoError(t, err)
		assert.Equal(t, dbmgr.ModeNormal, state.Mode, "loaded from this instance's document")
		assert.Equal(t, "sha256:on-disk", state.ManifestDigest, "the disk is the source of truth")
		assert.True(t, state.LastConfirmedCurrentAt.IsZero(), "stored confirmation ignored")
		assert.False(t, state.NewerAvailable, "stored newer_available ignored")

		javaState, err := s.Get(context.Background(), "java-db")
		require.NoError(t, err)
		assert.Equal(t, "sha256:java", javaState.ManifestDigest)
		assert.Equal(t, confirmed, javaState.LastConfirmedCurrentAt.UTC(), "digest matches the disk: confirmation kept")
	})
}
