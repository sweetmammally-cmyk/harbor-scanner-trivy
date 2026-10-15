package store

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

// Collections of the data plane (DEMAND section 10).
const (
	CollectionScans     = "scans"
	CollectionPlatforms = "platforms"
	CollectionDBState   = "db_state"
	CollectionDBChecks  = "db_checks"
)

// Scan states. A scan_id that is not stored is reported as "not_found" by the API.
const (
	ScanQueued   = "queued"
	ScanScanning = "scanning"
	ScanDone     = "done"
	ScanFailed   = "failed"
)

// Scan is a document of the scans collection. It is also the queue's job record.
// Times that are not known yet are nil, so they are absent from the document.
type Scan struct {
	ID string `bson:"_id"`
	// RequestID is omitted when empty, so scans without one do not collide on the
	// partial unique index.
	RequestID    string         `bson:"request_id,omitempty"`
	RequestedAt  time.Time      `bson:"requested_at"`
	CustomerIDs  []string       `bson:"customer_ids"`
	CustomerData map[string]any `bson:"customer_data,omitempty"`
	Image        Image          `bson:"image"`
	Options      ScanOptions    `bson:"options"`
	// ScannedPlatform is the platform scanned in a multi-platform image
	// (SCANNER_SCAN_PLATFORM); part of the cache and dedupe keys.
	ScannedPlatform string    `bson:"scanned_platform"`
	State           string    `bson:"state"`
	Trivy           TrivyInfo `bson:"trivy"`

	// Platforms are all result types found in the image. PlatformsFound and
	// PlatformsNotFound split the requested ones (Options.Platforms) by whether the
	// image has them: a requested platform that is not there is not a clean result.
	Platforms         []string `bson:"platforms"`
	PlatformsFound    []string `bson:"platforms_found,omitempty"`
	PlatformsNotFound []string `bson:"platforms_not_found,omitempty"`
	HasMorePlatforms  bool     `bson:"has_more_platforms"`
	// Summary counts the findings of the requested platforms by lowercase severity.
	Summary map[string]int `bson:"summary,omitempty"`
	// Truncated is set when more findings were found than SCANNER_SCAN_MAX_FINDINGS;
	// the summary counts stay complete.
	Truncated bool `bson:"truncated,omitempty"`
	// Report holds the stored findings; its shape is set by the scan runner (P7).
	// It is empty when the report is too large and stored in GridFS instead.
	Report         bson.M         `bson:"report,omitempty"`
	ReportGridFSID *bson.ObjectID `bson:"report_gridfs_id,omitempty"`

	QueuedAt    time.Time  `bson:"queued_at"`
	StartedAt   *time.Time `bson:"started_at,omitempty"`
	FinishedAt  *time.Time `bson:"finished_at,omitempty"`
	QueueWaitMS int64      `bson:"queue_wait_ms"`
	ScanMS      int64      `bson:"scan_ms"`
	TotalMS     int64      `bson:"total_ms"`

	Worker     string     `bson:"worker,omitempty"`
	LeaseUntil *time.Time `bson:"lease_until,omitempty"`
	Error      string     `bson:"error,omitempty"`
	// FailureClass is set on a failed scan (for example trivy_timeout).
	FailureClass string `bson:"failure_class,omitempty"`
}

// Image is the scanned image. Digest is the cache key.
type Image struct {
	Repository string `bson:"repository"`
	Name       string `bson:"name"`
	Tag        string `bson:"tag"`
	Digest     string `bson:"digest"`
	// MediaType is the manifest media type the tag resolved to (an image index
	// for a multi-architecture image; its handling is deferred).
	MediaType string `bson:"media_type,omitempty"`
}

// ScanOptions are what the request asked for.
type ScanOptions struct {
	Platforms []string `bson:"platforms"`
	Severity  []string `bson:"severity"`
}

// TrivyInfo records the Trivy and DB versions a scan used.
type TrivyInfo struct {
	Version          string    `bson:"version"`
	DBUpdatedAt      time.Time `bson:"db_updated_at"`
	DBManifestDigest string    `bson:"db_manifest_digest"`
}

// Platform is a document of the platforms collection: one per Trivy result type
// seen in any scan.
type Platform struct {
	ID            string    `bson:"_id"`
	FirstSeenAt   time.Time `bson:"first_seen_at"`
	LastSeenAt    time.Time `bson:"last_seen_at"`
	SeenCount     int64     `bson:"seen_count"`
	ExampleDigest string    `bson:"example_digest"`
}

// DBStateDocument is a document of the db_state collection: one per scanner
// instance and DB kind, with _id "<instance_id>:<db>" (db is "db" or "java-db").
type DBStateDocument struct {
	ID         string `bson:"_id"`
	InstanceID string `bson:"instance_id"`
	DB         string `bson:"db"`
	// UpdatedAt is set on every write; the TTL index on it removes the state of
	// instances that are gone (SCANNER_DB_STATE_RETENTION).
	UpdatedAt     time.Time `bson:"updated_at"`
	dbmgr.DBState `bson:",inline"`
}

// DBCheck is a document of the db_checks collection: the result of one source
// in one update run. Old documents expire through a TTL index on at (P5-3).
// ID is "<instance_id>:<db>:<run_started_at>:<source>" (see DBCheckID), so
// writing the same row again replaces it instead of adding a copy.
type DBCheck struct {
	ID                 string    `bson:"_id"`
	InstanceID         string    `bson:"instance_id"`
	DB                 string    `bson:"db"`
	At                 time.Time `bson:"at"`
	dbmgr.SourceResult `bson:",inline"`
}
