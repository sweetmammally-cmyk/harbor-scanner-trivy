package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// Want is what a stored result must match to serve a request from the cache
// (DEMAND section 6).
type Want struct {
	Digest          string
	ScannedPlatform string
	TrivyVersion    string
	Options         store.ScanOptions
	// DBUpdatedAt is the installed DB's UpdatedAt.
	DBUpdatedAt time.Time
}

// Serves reports whether the scan's stored result serves the request: the
// same digest, scanned platform and Trivy version, a scope that covers the
// request, and a DB at least as new as the installed one. Validity is decided
// by the DB version, never by time. The caller checks force and the active scan.
func Serves(scan store.Scan, want Want) bool {
	result := scan.Result
	if result == nil || scan.DB == nil || want.DBUpdatedAt.IsZero() {
		return false
	}
	// MongoDB keeps times in milliseconds, the installed DB's UpdatedAt has
	// nanoseconds: compare at MongoDB's precision, as FindCopySource does.
	installed := want.DBUpdatedAt.Truncate(time.Millisecond)
	return result.Digest == want.Digest &&
		result.ScannedPlatform == want.ScannedPlatform &&
		result.TrivyVersion == want.TrivyVersion &&
		Covers(store.ScanOptions{Platforms: result.Platforms, Severity: result.Severity}, want.Options) &&
		!scan.DB.UpdatedAt.Before(installed)
}

// requestFields are the fields a request overwrites on a hit or a copy.
func requestFields(request store.Scan) (bson.D, bson.A) {
	set := bson.D{
		{Key: "customer_ids", Value: literal(request.CustomerIDs)},
		{Key: "requested_at", Value: literal(request.RequestedAt)},
		{Key: "received_at", Value: literal(request.ReceivedAt)},
	}
	unset := bson.A{"error", "failure_class"}
	if request.CustomerData != nil {
		set = append(set, bson.E{Key: "customer_data", Value: literal(request.CustomerData)})
	} else {
		unset = append(unset, "customer_data")
	}
	if request.LastRequestID != "" {
		set = append(set, bson.E{Key: "last_request_id", Value: literal(request.LastRequestID)})
	} else {
		unset = append(unset, "last_request_id")
	}
	return set, unset
}

// Renew records a cache hit on the tag's document (DEMAND section 6):
// confirmed_at = now, db.freshness for this request, the request's customer
// fields and last_request_id, state done. It applies only while the document
// is not queued or scanning and its result is still for digest; otherwise
// store.ErrNotFound (a concurrent request changed it: no hit).
func (q *Queue) Renew(ctx context.Context, request store.Scan, digest, freshness string) (store.Scan, error) {
	set, unset := requestFields(request)
	set = append(set,
		bson.E{Key: "state", Value: store.ScanDone},
		bson.E{Key: "confirmed_at", Value: "$$NOW"},
		bson.E{Key: "db.freshness", Value: literal(freshness)},
	)
	filter := bson.D{
		{Key: "_id", Value: request.ID},
		{Key: "state", Value: bson.D{{Key: "$nin", Value: bson.A{store.ScanQueued, store.ScanScanning}}}},
		{Key: "result.digest", Value: digest},
	}
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	var renewed store.Scan
	err := q.scans.FindOneAndUpdate(ctx, filter,
		mongo.Pipeline{{{Key: "$set", Value: set}}, {{Key: "$unset", Value: unset}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&renewed)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return store.Scan{}, store.ErrNotFound
	}
	if err != nil {
		return store.Scan{}, fmt.Errorf("renewing scan %s: %w", request.ID, err)
	}
	return renewed, nil
}

// FindCopySource finds another tag's document whose result serves want (see
// Serves), most recently confirmed first. The source may be queued or
// scanning: its result is still valid. store.ErrNotFound when there is none.
func (q *Queue) FindCopySource(ctx context.Context, want Want, exceptID string) (store.Scan, error) {
	if want.DBUpdatedAt.IsZero() {
		return store.Scan{}, store.ErrNotFound
	}
	filter := bson.D{
		{Key: "result.digest", Value: want.Digest},
		{Key: "_id", Value: bson.D{{Key: "$ne", Value: exceptID}}},
		{Key: "result.scanned_platform", Value: want.ScannedPlatform},
		{Key: "result.trivy_version", Value: want.TrivyVersion},
		{Key: "result.platforms", Value: bson.D{{Key: "$all", Value: want.Options.Platforms}}},
		{Key: "result.severity", Value: bson.D{{Key: "$all", Value: want.Options.Severity}}},
		{Key: "db.updated_at", Value: bson.D{{Key: "$gte", Value: want.DBUpdatedAt}}},
	}
	opts := options.FindOne().SetSort(bson.D{{Key: "confirmed_at", Value: -1}})
	return q.findOneWith(ctx, filter, opts)
}

// SaveCopy stores a result copied from another tag in the tag's document
// (state done, confirmed_at now): it creates the document when exists is
// false, otherwise it updates it while it is not queued or scanning. A
// concurrent change gives store.ErrNotFound (no hit).
func (q *Queue) SaveCopy(ctx context.Context, copied store.Scan, exists bool) error {
	ctx, cancel := q.client.OperationContext(ctx)
	defer cancel()
	if !exists {
		now := time.Now()
		copied.ConfirmedAt = &now
		copied.CreatedAt = now
		_, err := q.scans.InsertOne(ctx, copied)
		if mongo.IsDuplicateKeyError(err) {
			return store.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("saving a copied result in scan %s: %w", copied.ID, err)
		}
		return nil
	}

	set, unset := requestFields(copied)
	set = append(set,
		bson.E{Key: "state", Value: store.ScanDone},
		bson.E{Key: "confirmed_at", Value: "$$NOW"},
		bson.E{Key: "image", Value: literal(copied.Image)},
		bson.E{Key: "reference", Value: literal(copied.Reference)},
		bson.E{Key: "options", Value: literal(copied.Options)},
		bson.E{Key: "result", Value: literal(copied.Result)},
		bson.E{Key: "db", Value: literal(copied.DB)},
	)
	filter := bson.D{
		{Key: "_id", Value: copied.ID},
		{Key: "state", Value: bson.D{{Key: "$nin", Value: bson.A{store.ScanQueued, store.ScanScanning}}}},
	}
	result, err := q.scans.UpdateOne(ctx, filter, mongo.Pipeline{{{Key: "$set", Value: set}}, {{Key: "$unset", Value: unset}}})
	if err != nil {
		return fmt.Errorf("saving a copied result in scan %s: %w", copied.ID, err)
	}
	if result.MatchedCount == 0 {
		return store.ErrNotFound
	}
	return nil
}
