package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a document does not exist.
var ErrNotFound = errors.New("not found")

// ScanRepository stores scans. The queue (pkg/v2/queue) does the queue writes;
// the cache and list queries come with the API (P9).
type ScanRepository interface {
	// Create stores a new scan document; a document with the same _id (the same
	// image tag) is an error.
	Create(ctx context.Context, scan Scan) error
	Get(ctx context.Context, id string) (Scan, error)
}

// PlatformRepository stores the platforms (Trivy result types) seen in scans.
type PlatformRepository interface {
	// Seen records that the image digest has these platform types: new types are
	// created with first_seen_at and example_digest; every type gets last_seen_at
	// and one more seen_count.
	Seen(ctx context.Context, types []string, digest string, at time.Time) error
	List(ctx context.Context) ([]Platform, error)
}

// DBCheckRepository stores the history of DB pre-checks and downloads.
type DBCheckRepository interface {
	Add(ctx context.Context, checks []DBCheck) error
	// Recent returns the newest checks of a DB ("db" or "java-db"), newest first.
	Recent(ctx context.Context, db string, limit int) ([]DBCheck, error)
}

// The memory fakes and the MongoDB repositories implement the same interfaces.
var (
	_ ScanRepository     = (*MongoScans)(nil)
	_ ScanRepository     = (*MemoryScans)(nil)
	_ PlatformRepository = (*MongoPlatforms)(nil)
	_ PlatformRepository = (*MemoryPlatforms)(nil)
	_ DBCheckRepository  = (*MongoDBChecks)(nil)
	_ DBCheckRepository  = (*MemoryDBChecks)(nil)
)
