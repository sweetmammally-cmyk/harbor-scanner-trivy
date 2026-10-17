package store

import (
	"crypto/sha256"
	"fmt"
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

// ScanID is the _id of an image tag's scan document, and the scan_id of the
// API: the lowercase hex sha256 of "<repository>/<name>:<tag>". There is one
// document per tag; a new scan of the tag overwrites the previous result.
func ScanID(image Image) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(image.Repository+"/"+image.Name+":"+image.Tag)))
}

// Scan is a document of the scans collection: the current state of one image
// tag (see ScanID). It is also the queue's job record. The state, options,
// timings and queue fields describe the current attempt; Result, DB and
// ConfirmedAt describe the last successful scan and are replaced only when a new
// scan succeeds (or a cache hit renews them). Times that are not known yet are
// nil, so they are absent from the document.
type Scan struct {
	ID string `bson:"_id"`
	// LastRequestID is the caller's optional correlation id of the last request
	// (1-128 characters). It is logged, not unique.
	LastRequestID string         `bson:"last_request_id,omitempty"`
	RequestedAt   time.Time      `bson:"requested_at"`
	CustomerIDs   []string       `bson:"customer_ids"`
	CustomerData  map[string]any `bson:"customer_data,omitempty"`
	// Image is the tag and the digest it resolved to at the last enqueue.
	Image Image `bson:"image"`
	// Options are the scope of the current attempt: the request's, or the union
	// with the stored result's scope when the digest is the same.
	Options ScanOptions `bson:"options"`
	// Reference is what the scan runner scans: host/repository/name@digest.
	Reference string `bson:"reference"`
	State     string `bson:"state"`

	QueuedAt    time.Time  `bson:"queued_at"`
	StartedAt   *time.Time `bson:"started_at,omitempty"`
	FinishedAt  *time.Time `bson:"finished_at,omitempty"`
	QueueWaitMS int64      `bson:"queue_wait_ms"`
	ScanMS      int64      `bson:"scan_ms"`
	TotalMS     int64      `bson:"total_ms"`

	Worker     string     `bson:"worker,omitempty"`
	LeaseUntil *time.Time `bson:"lease_until,omitempty"`
	// Attempt counts the claims of the current attempt; it fences the worker's writes.
	Attempt int `bson:"attempt"`
	// Priority is reserved for queue priorities, which are deferred (DEMAND section 14).
	Priority *int `bson:"priority,omitempty"`
	// Error and FailureClass are set when the current attempt failed (for
	// example trivy_timeout). The last good result stays in place.
	Error        string `bson:"error,omitempty"`
	FailureClass string `bson:"failure_class,omitempty"`

	// Result is the last successful scan; nil until the first one.
	Result *ScanResult `bson:"result,omitempty"`
	// DB is the DB the result's findings come from, with its freshness against
	// the max_db_age of the request that produced or last renewed the result.
	DB *ScanDB `bson:"db,omitempty"`
	// ConfirmedAt is when the result was produced or last renewed by a cache hit.
	ConfirmedAt *time.Time `bson:"confirmed_at,omitempty"`
}

// ScanResult is the last successful scan of a tag.
type ScanResult struct {
	// Digest is the image digest that was scanned (the tag may have moved since).
	Digest string `bson:"digest"`
	// Platforms and Severity are the scope that was scanned; a request is covered
	// when they contain all of its platforms and severities.
	Platforms       []string `bson:"platforms"`
	Severity        []string `bson:"severity"`
	ScannedPlatform string   `bson:"scanned_platform"`
	TrivyVersion    string   `bson:"trivy_version"`
	// ImagePlatformTypes are all result types found in the image, scanned or not.
	ImagePlatformTypes []string `bson:"image_platform_types"`
	// Summary counts the findings of the scanned platforms by lowercase severity,
	// at every severity; SummaryByPlatform splits it by platform (only the
	// scanned platforms that the image has).
	Summary           map[string]int            `bson:"summary"`
	SummaryByPlatform map[string]map[string]int `bson:"summary_by_platform"`
	// Truncated is set when more findings were found than SCANNER_SCAN_MAX_FINDINGS;
	// the summary counts stay complete.
	Truncated bool `bson:"truncated,omitempty"`
	// Report holds the findings ({"findings": [...]}). It is empty when the
	// report is too large and stored in GridFS instead.
	Report         bson.M         `bson:"report,omitempty"`
	ReportGridFSID *bson.ObjectID `bson:"report_gridfs_id,omitempty"`
}

// ScanDB is the DB block of a scan document.
type ScanDB struct {
	UpdatedAt      time.Time `bson:"updated_at"`
	ManifestDigest string    `bson:"manifest_digest"`
	// Freshness is dbmgr.FreshnessOK or dbmgr.FreshnessStale.
	Freshness string `bson:"freshness"`
}

// Image is the scanned image tag.
type Image struct {
	Repository string `bson:"repository"`
	Name       string `bson:"name"`
	Tag        string `bson:"tag"`
	Digest     string `bson:"digest"`
	// MediaType is the manifest media type the tag resolved to (an image index
	// for a multi-architecture image; its handling is deferred).
	MediaType string `bson:"media_type,omitempty"`
}

// ScanOptions are the scope of a scan.
type ScanOptions struct {
	Platforms []string `bson:"platforms"`
	Severity  []string `bson:"severity"`
	// MaxDBAge is the request's max_db_age, for the on-demand DB refresh and the
	// stored freshness.
	MaxDBAge time.Duration `bson:"max_db_age,omitempty"`
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
