package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoScans is the MongoDB ScanRepository. Every call has the operation deadline.
type MongoScans struct {
	client *Client
}

func NewMongoScans(client *Client) *MongoScans {
	return &MongoScans{client: client}
}

func (r *MongoScans) Create(ctx context.Context, scan Scan) error {
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	_, err := r.client.Database().Collection(CollectionScans).InsertOne(ctx, scan)
	// The partial unique index request_id_unique names itself in the error.
	if mongo.IsDuplicateKeyError(err) && strings.Contains(err.Error(), "request_id_unique") {
		return ErrDuplicateRequestID
	}
	if err != nil {
		return fmt.Errorf("creating scan %s: %w", scan.ID, err)
	}
	return nil
}

func (r *MongoScans) Get(ctx context.Context, id string) (Scan, error) {
	return r.findOne(ctx, bson.D{{Key: "_id", Value: id}}, nil)
}

func (r *MongoScans) GetByRequestID(ctx context.Context, requestID string) (Scan, error) {
	return r.findOne(ctx, bson.D{{Key: "request_id", Value: requestID}}, nil)
}

func (r *MongoScans) LastDone(ctx context.Context, digest string) (Scan, error) {
	return r.findOne(ctx,
		bson.D{{Key: "image.digest", Value: digest}, {Key: "state", Value: ScanDone}},
		bson.D{{Key: "finished_at", Value: -1}})
}

func (r *MongoScans) findOne(ctx context.Context, filter bson.D, sort bson.D) (Scan, error) {
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	opts := options.FindOne()
	if sort != nil {
		opts.SetSort(sort)
	}
	var scan Scan
	err := r.client.Database().Collection(CollectionScans).FindOne(ctx, filter, opts).Decode(&scan)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Scan{}, ErrNotFound
	}
	if err != nil {
		return Scan{}, fmt.Errorf("reading scan: %w", err)
	}
	return scan, nil
}

// MongoPlatforms is the MongoDB PlatformRepository.
type MongoPlatforms struct {
	client *Client
}

func NewMongoPlatforms(client *Client) *MongoPlatforms {
	return &MongoPlatforms{client: client}
}

func (r *MongoPlatforms) Seen(ctx context.Context, types []string, digest string, at time.Time) error {
	collection := r.client.Database().Collection(CollectionPlatforms)
	for _, platformType := range types {
		update := bson.D{
			{Key: "$setOnInsert", Value: bson.D{{Key: "first_seen_at", Value: at}, {Key: "example_digest", Value: digest}}},
			{Key: "$set", Value: bson.D{{Key: "last_seen_at", Value: at}}},
			{Key: "$inc", Value: bson.D{{Key: "seen_count", Value: 1}}},
		}
		opCtx, cancel := r.client.OperationContext(ctx)
		_, err := collection.UpdateOne(opCtx, bson.D{{Key: "_id", Value: platformType}}, update, options.UpdateOne().SetUpsert(true))
		// Two scans inserting the same new type at once: one gets a duplicate key
		// error and the document exists now, so the update is simply repeated.
		if mongo.IsDuplicateKeyError(err) {
			_, err = collection.UpdateOne(opCtx, bson.D{{Key: "_id", Value: platformType}}, update)
		}
		cancel()
		if err != nil {
			return fmt.Errorf("recording platform %s: %w", platformType, err)
		}
	}
	return nil
}

func (r *MongoPlatforms) List(ctx context.Context) ([]Platform, error) {
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	cursor, err := r.client.Database().Collection(CollectionPlatforms).Find(ctx, bson.D{},
		options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("listing platforms: %w", err)
	}
	var platforms []Platform
	if err = cursor.All(ctx, &platforms); err != nil {
		return nil, fmt.Errorf("listing platforms: %w", err)
	}
	return platforms, nil
}

// MongoDBChecks is the MongoDB DBCheckRepository. Old documents expire through
// the TTL index on at.
type MongoDBChecks struct {
	client *Client
}

func NewMongoDBChecks(client *Client) *MongoDBChecks {
	return &MongoDBChecks{client: client}
}

// Add writes the checks with an upsert on their _id, so writing the same rows
// again (a retried flush) never adds copies.
func (r *MongoDBChecks) Add(ctx context.Context, checks []DBCheck) error {
	if len(checks) == 0 {
		return nil
	}
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	writes := make([]mongo.WriteModel, len(checks))
	for i, check := range checks {
		writes[i] = mongo.NewReplaceOneModel().SetFilter(bson.D{{Key: "_id", Value: check.ID}}).
			SetReplacement(check).SetUpsert(true)
	}
	_, err := r.client.Database().Collection(CollectionDBChecks).BulkWrite(ctx, writes, options.BulkWrite().SetOrdered(false))
	if err != nil {
		return fmt.Errorf("adding DB checks: %w", err)
	}
	return nil
}

func (r *MongoDBChecks) Recent(ctx context.Context, db string, limit int) ([]DBCheck, error) {
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	cursor, err := r.client.Database().Collection(CollectionDBChecks).Find(ctx,
		bson.D{{Key: "db", Value: db}},
		options.Find().SetSort(bson.D{{Key: "at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, fmt.Errorf("reading DB checks: %w", err)
	}
	var checks []DBCheck
	if err = cursor.All(ctx, &checks); err != nil {
		return nil, fmt.Errorf("reading DB checks: %w", err)
	}
	return checks, nil
}
