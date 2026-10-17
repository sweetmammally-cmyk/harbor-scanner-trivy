package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// SchemaVersion is the data plane schema version this code expects.
// 2: the queue indexes (active_key_unique, state_lease_until).
// 3: one scan document per image tag; no request_id_unique or active_key_unique.
// Nothing was deployed before 3, so there is no migration: databases of older
// versions are recreated.
const SchemaVersion = 3

// CollectionSchemaVersion holds one document, _id "schema", with the stored version.
const CollectionSchemaVersion = "schema_version"

// The TTL indexes: old db_checks rows and the db_state of instances that are gone expire.
var (
	dbChecksTTL = index{collection: CollectionDBChecks, name: "at_ttl", keys: bson.D{{Key: "at", Value: 1}}}
	dbStateTTL  = index{collection: CollectionDBState, name: "updated_at_ttl", keys: bson.D{{Key: "updated_at", Value: 1}}}
)

// MongoDB error codes for an index that exists with other options or keys.
const (
	codeIndexOptionsConflict  = 85
	codeIndexKeySpecsConflict = 86
	codeNamespaceNotFound     = 26
)

type schemaVersionDocument struct {
	ID        string    `bson:"_id"`
	Version   int       `bson:"version"`
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
}

// index is an index we create, with its name for clear errors.
type index struct {
	collection string
	name       string
	keys       bson.D
	options    *options.IndexOptionsBuilder
}

// scansIndexes are the indexes of the scans collection (DEMAND section 10).
func scansIndexes() []index {
	return []index{
		{
			// Also finds other tags with the same digest for the cache (prefix image.digest).
			collection: CollectionScans,
			name:       "image_digest_state_finished_at",
			keys:       bson.D{{Key: "image.digest", Value: 1}, {Key: "state", Value: 1}, {Key: "finished_at", Value: 1}},
			options:    options.Index(),
		},
		{
			collection: CollectionScans,
			name:       "customer_ids_finished_at",
			keys:       bson.D{{Key: "customer_ids", Value: 1}, {Key: "finished_at", Value: 1}},
			options:    options.Index(),
		},
		{
			collection: CollectionScans,
			name:       "state_queued_at",
			keys:       bson.D{{Key: "state", Value: 1}, {Key: "queued_at", Value: 1}},
			options:    options.Index(),
		},
		{
			// For the reaper: expired leases of scanning scans.
			collection: CollectionScans,
			name:       "state_lease_until",
			keys:       bson.D{{Key: "state", Value: 1}, {Key: "lease_until", Value: 1}},
			options:    options.Index(),
		},
	}
}

// EnsureSchema prepares the database (DEMAND section 10): it checks the stored
// schema version, runs migrations when it is older (none yet), creates the
// indexes and the db_checks TTL index, and records the version. It is safe to
// run again and from several replicas at once. It never drops an index.
func (c *Client) EnsureSchema(ctx context.Context) error {
	stored, err := c.storedSchemaVersion(ctx)
	if err != nil {
		return err
	}
	if stored > SchemaVersion {
		return fmt.Errorf("stored schema version %d is newer than this scanner's %d: run a newer scanner", stored, SchemaVersion)
	}
	// Migrations from older versions go here. There are none yet.

	for _, ix := range scansIndexes() {
		if err = c.createIndex(ctx, ix); err != nil {
			return err
		}
	}
	if err = c.ensureTTL(ctx, dbChecksTTL, c.dbChecksRetention); err != nil {
		return err
	}
	if err = c.ensureTTL(ctx, dbStateTTL, c.dbStateRetention); err != nil {
		return err
	}

	if stored < SchemaVersion {
		opCtx, cancel := c.OperationContext(ctx)
		defer cancel()
		_, err = c.db.Collection(CollectionSchemaVersion).UpdateOne(opCtx,
			bson.D{{Key: "_id", Value: "schema"}, {Key: "version", Value: stored}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "version", Value: SchemaVersion}, {Key: "updated_at", Value: time.Now()}}}})
		if err != nil {
			return fmt.Errorf("setting schema version: %w", err)
		}
	}
	return nil
}

// storedSchemaVersion creates the schema_version document if it is missing
// (upsert with $setOnInsert, so concurrent replicas cannot collide) and returns
// the stored version.
func (c *Client) storedSchemaVersion(ctx context.Context) (int, error) {
	collection := c.db.Collection(CollectionSchemaVersion)

	opCtx, cancel := c.OperationContext(ctx)
	defer cancel()
	now := time.Now()
	_, err := collection.UpdateOne(opCtx,
		bson.D{{Key: "_id", Value: "schema"}},
		bson.D{{Key: "$setOnInsert", Value: bson.D{
			{Key: "version", Value: SchemaVersion}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now},
		}}},
		options.UpdateOne().SetUpsert(true))
	// Two replicas inserting at the same moment: one gets a duplicate key error, and
	// the document exists either way.
	if err != nil && !mongo.IsDuplicateKeyError(err) {
		return 0, fmt.Errorf("creating schema_version: %w", err)
	}

	var document schemaVersionDocument
	if err = collection.FindOne(opCtx, bson.D{{Key: "_id", Value: "schema"}}).Decode(&document); err != nil {
		return 0, fmt.Errorf("reading schema_version: %w", err)
	}
	return document.Version, nil
}

func (c *Client) createIndex(ctx context.Context, ix index) error {
	opCtx, cancel := c.OperationContext(ctx)
	defer cancel()
	_, err := c.db.Collection(ix.collection).Indexes().CreateOne(opCtx,
		mongo.IndexModel{Keys: ix.keys, Options: ix.options.SetName(ix.name)})
	if isIndexConflict(err) {
		return fmt.Errorf("index %s.%s conflicts with an existing index; it is never dropped automatically, "+
			"fix or drop it by hand: %w", ix.collection, ix.name, err)
	}
	if err != nil {
		return fmt.Errorf("creating index %s.%s: %w", ix.collection, ix.name, err)
	}
	return nil
}

func isIndexConflict(err error) bool {
	var serverError mongo.ServerError
	return errors.As(err, &serverError) &&
		(serverError.HasErrorCode(codeIndexOptionsConflict) || serverError.HasErrorCode(codeIndexKeySpecsConflict))
}

// ensureTTL creates the TTL index ix (one date field) with the retention, or
// updates its expireAfterSeconds with collMod when the retention changed.
func (c *Client) ensureTTL(ctx context.Context, ix index, retention time.Duration) error {
	// A zero TTL would delete every document at once: never create one by mistake.
	if retention < time.Second {
		return fmt.Errorf("index %s.%s: retention %s is too short", ix.collection, ix.name, retention)
	}
	want := int64(retention / time.Second)

	current, found, err := c.ttlSeconds(ctx, ix)
	if err != nil {
		return err
	}
	if found && current == want {
		return nil
	}
	if found {
		opCtx, cancel := c.OperationContext(ctx)
		defer cancel()
		err = c.db.RunCommand(opCtx, bson.D{
			{Key: "collMod", Value: ix.collection},
			{Key: "index", Value: bson.D{{Key: "name", Value: ix.name}, {Key: "expireAfterSeconds", Value: want}}},
		}).Err()
		if err != nil {
			return fmt.Errorf("updating index %s.%s with collMod: %w", ix.collection, ix.name, err)
		}
		slog.Info("updated a retention", slog.String("index", ix.collection+"."+ix.name),
			slog.Int64("from_seconds", current), slog.Int64("to_seconds", want))
		return nil
	}

	ix.options = options.Index().SetExpireAfterSeconds(int32(want))
	return c.createIndex(ctx, ix)
}

// ttlSeconds returns the expireAfterSeconds of the TTL index ix, if it exists.
func (c *Client) ttlSeconds(ctx context.Context, ix index) (int64, bool, error) {
	opCtx, cancel := c.OperationContext(ctx)
	defer cancel()
	cursor, err := c.db.Collection(ix.collection).Indexes().List(opCtx)
	var serverError mongo.ServerError
	if errors.As(err, &serverError) && serverError.HasErrorCode(codeNamespaceNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("listing indexes of %s: %w", ix.collection, err)
	}
	var indexes []bson.M
	if err = cursor.All(opCtx, &indexes); err != nil {
		return 0, false, fmt.Errorf("listing indexes of %s: %w", ix.collection, err)
	}

	for _, existing := range indexes {
		if existing["name"] != ix.name {
			continue
		}
		switch seconds := existing["expireAfterSeconds"].(type) {
		case int32:
			return int64(seconds), true, nil
		case int64:
			return seconds, true, nil
		case float64:
			return int64(seconds), true, nil
		}
		// An index with our name but no TTL: createIndexes reports the conflict.
		return 0, false, nil
	}
	return 0, false, nil
}
