//go:build integration

package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongooptions "go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func schemaConfig(addr, database string, retention time.Duration) config.Config {
	cfg := mongoConfig(addr)
	cfg.MongoDB = database
	cfg.DBChecksRetention = retention
	return cfg
}

func newClient(t *testing.T, cfg config.Config) *store.Client {
	client, err := store.NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client
}

// monitor runs the client's Monitor with a short interval until the test ends.
func monitor(t *testing.T, client *store.Client) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go client.Monitor(ctx, 100*time.Millisecond)
}

// indexes returns the index documents of a collection by name.
func indexes(t *testing.T, client *store.Client, collection string) map[string]bson.M {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	cursor, err := client.Database().Collection(collection).Indexes().List(ctx)
	require.NoError(t, err)
	var list []bson.M
	require.NoError(t, cursor.All(ctx, &list))
	byName := map[string]bson.M{}
	for _, ix := range list {
		byName[ix["name"].(string)] = ix
	}
	return byName
}

func schemaVersion(t *testing.T, client *store.Client) bson.M {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	var document bson.M
	require.NoError(t, client.Database().Collection(store.CollectionSchemaVersion).
		FindOne(ctx, bson.M{"_id": "schema"}).Decode(&document))
	return document
}

func insert(t *testing.T, client *store.Client, collection string, document any) error {
	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	_, err := client.Database().Collection(collection).InsertOne(ctx, document)
	return err
}

func TestSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}
	mongoAddr := startMongo(t)
	const retention = 30 * 24 * time.Hour

	t.Run("two replicas ensure the schema at the same time without errors", func(t *testing.T) {
		for round := 0; round < 5; round++ {
			cfg := schemaConfig(mongoAddr, "concurrent_"+string(rune('a'+round)), retention)
			first, second := newClient(t, cfg), newClient(t, cfg)

			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i, client := range []*store.Client{first, second} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs[i] = client.EnsureSchema(context.Background())
				}()
			}
			wg.Wait()

			require.NoError(t, errs[0], "round %d", round)
			require.NoError(t, errs[1], "round %d", round)
			assert.EqualValues(t, store.SchemaVersion, schemaVersion(t, first)["version"])
		}
	})

	t.Run("running ensure schema twice changes nothing", func(t *testing.T) {
		client := newClient(t, schemaConfig(mongoAddr, "twice", retention))
		require.NoError(t, client.EnsureSchema(context.Background()))
		scansBefore, checksBefore, versionBefore := indexes(t, client, "scans"), indexes(t, client, "db_checks"), schemaVersion(t, client)

		require.NoError(t, client.EnsureSchema(context.Background()))

		assert.Equal(t, scansBefore, indexes(t, client, "scans"))
		assert.Equal(t, checksBefore, indexes(t, client, "db_checks"))
		assert.Equal(t, versionBefore, schemaVersion(t, client))
		assert.Contains(t, scansBefore, "request_id_unique")
		assert.Contains(t, scansBefore, "image_digest_state_finished_at")
		assert.Contains(t, scansBefore, "customer_ids_finished_at")
		assert.Contains(t, scansBefore, "state_queued_at")
	})

	t.Run("request_id: absent twice is fine, a duplicate is rejected", func(t *testing.T) {
		client := newClient(t, schemaConfig(mongoAddr, "request_ids", retention))
		require.NoError(t, client.EnsureSchema(context.Background()))
		now := time.Now()

		require.NoError(t, insert(t, client, store.CollectionScans, store.Scan{ID: "a", State: store.ScanQueued, QueuedAt: now}))
		require.NoError(t, insert(t, client, store.CollectionScans, store.Scan{ID: "b", State: store.ScanQueued, QueuedAt: now}))
		require.NoError(t, insert(t, client, store.CollectionScans, store.Scan{ID: "c", RequestID: "req-1", State: store.ScanQueued, QueuedAt: now}))
		err := insert(t, client, store.CollectionScans, store.Scan{ID: "d", RequestID: "req-1", State: store.ScanQueued, QueuedAt: now})

		assert.True(t, mongo.IsDuplicateKeyError(err), "%v", err)
		assert.EqualValues(t, bson.M{"request_id": bson.M{"$type": "string"}},
			bsonToMap(indexes(t, client, "scans")["request_id_unique"]["partialFilterExpression"]))
	})

	t.Run("db_checks TTL follows the retention, updated with collMod", func(t *testing.T) {
		client := newClient(t, schemaConfig(mongoAddr, "ttl", retention))
		require.NoError(t, client.EnsureSchema(context.Background()))
		ttl := indexes(t, client, "db_checks")["at_ttl"]
		assert.EqualValues(t, 30*24*3600, ttl["expireAfterSeconds"])
		assert.Equal(t, bson.M{"at": int32(1)}, bsonToMap(ttl["key"]))

		changed := newClient(t, schemaConfig(mongoAddr, "ttl", 7*24*time.Hour))
		require.NoError(t, changed.EnsureSchema(context.Background()))

		assert.EqualValues(t, 7*24*3600, indexes(t, changed, "db_checks")["at_ttl"]["expireAfterSeconds"])
	})

	t.Run("a conflicting index is reported, kept, and the replica is not ready", func(t *testing.T) {
		cfg := schemaConfig(mongoAddr, "conflict", retention)
		setup := newClient(t, cfg)
		ctx, cancel := setup.OperationContext(context.Background())
		defer cancel()
		_, err := setup.Database().Collection("scans").Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys: bson.D{{Key: "state", Value: 1}}, Options: mongooptions.Index().SetName("state_queued_at"),
		})
		require.NoError(t, err)

		err = setup.EnsureSchema(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "index scans.state_queued_at conflicts with an existing index")

		client := newClient(t, cfg)
		monitor(t, client)
		require.Eventually(t, client.Up, 15*time.Second, 50*time.Millisecond)
		time.Sleep(500 * time.Millisecond)
		assert.False(t, client.Ready())
		assert.Equal(t, bson.M{"state": int32(1)}, bsonToMap(indexes(t, client, "scans")["state_queued_at"]["key"]),
			"the existing index is never dropped or recreated")
	})

	t.Run("a newer stored schema version keeps the replica not ready", func(t *testing.T) {
		cfg := schemaConfig(mongoAddr, "newer", retention)
		setup := newClient(t, cfg)
		require.NoError(t, insert(t, setup, store.CollectionSchemaVersion, bson.M{"_id": "schema", "version": 99}))

		err := setup.EnsureSchema(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stored schema version 99 is newer than this scanner's 1")

		client := newClient(t, cfg)
		monitor(t, client)
		require.Eventually(t, client.Up, 15*time.Second, 50*time.Millisecond)
		time.Sleep(500 * time.Millisecond)
		assert.False(t, client.Ready())
		assert.EqualValues(t, 99, schemaVersion(t, client)["version"], "the stored version is not touched")
	})

	t.Run("an older stored schema version is migrated, then set to the current one", func(t *testing.T) {
		client := newClient(t, schemaConfig(mongoAddr, "older", retention))
		require.NoError(t, insert(t, client, store.CollectionSchemaVersion, bson.M{"_id": "schema", "version": 0}))

		require.NoError(t, client.EnsureSchema(context.Background()))

		assert.EqualValues(t, store.SchemaVersion, schemaVersion(t, client)["version"])
		assert.Contains(t, indexes(t, client, "scans"), "request_id_unique")
	})

	t.Run("Mongo down at startup: indexes are created after it comes back", func(t *testing.T) {
		proxy := newForwarder(t, mongoAddr)
		client := newClient(t, schemaConfig(proxy.addr, "late", retention))
		monitor(t, client)

		time.Sleep(3 * time.Second)
		assert.False(t, client.Ready())

		proxy.start(t)
		require.Eventually(t, client.Ready, 30*time.Second, 50*time.Millisecond)
		assert.Contains(t, indexes(t, client, "scans"), "request_id_unique")
		assert.Contains(t, indexes(t, client, "db_checks"), "at_ttl")
	})
}

// bsonToMap turns a decoded sub-document (bson.D or bson.M) into a bson.M.
func bsonToMap(value any) bson.M {
	switch document := value.(type) {
	case bson.M:
		result := bson.M{}
		for key, item := range document {
			result[key] = normalize(item)
		}
		return result
	case bson.D:
		result := bson.M{}
		for _, element := range document {
			result[element.Key] = normalize(element.Value)
		}
		return result
	}
	return nil
}

func normalize(value any) any {
	switch value.(type) {
	case bson.M, bson.D:
		return bsonToMap(value)
	}
	return value
}
