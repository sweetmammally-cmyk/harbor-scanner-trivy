package store

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

// keysOf marshals v to BSON and returns its top-level field names, sorted.
func keysOf(t *testing.T, v any) []string {
	t.Helper()
	data, err := bson.Marshal(v)
	require.NoError(t, err)
	var doc bson.M
	require.NoError(t, bson.Unmarshal(data, &doc))
	var keys []string
	for key := range doc {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// roundTrip marshals v to BSON and decodes it into out.
func roundTrip(t *testing.T, v any, out any) {
	t.Helper()
	data, err := bson.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, bson.Unmarshal(data, out))
}

func sorted(keys ...string) []string {
	sort.Strings(keys)
	return keys
}

// BSON stores times in milliseconds and UTC.
var at = time.Date(2026, 10, 15, 10, 0, 0, 123000000, time.UTC)

func TestScanID(t *testing.T) {
	id := ScanID(Image{Repository: "customer-123", Name: "app", Tag: "v1.2.0", Digest: "sha256:ignored"})

	// echo -n "customer-123/app:v1.2.0" | sha256sum
	assert.Equal(t, "d14d146c132c1135daaa524162a756801961683ac87eb127b68d121a96b1660b", id)
	assert.Equal(t, id, ScanID(Image{Repository: "customer-123", Name: "app", Tag: "v1.2.0", Digest: "sha256:other"}),
		"the digest is not part of the id: one document per tag")
	assert.NotEqual(t, id, ScanID(Image{Repository: "customer-123", Name: "app", Tag: "v1.2.1"}))
	assert.Regexp(t, "^[0-9a-f]{64}$", id)
}

func TestScan_BSON(t *testing.T) {
	started := at.Add(time.Second)
	finished := at.Add(5 * time.Second)
	gridFSID := bson.NewObjectID()
	priority := 1
	done := Scan{
		ID:            "scan-1",
		LastRequestID: "req-1",
		RequestedAt:   at,
		CustomerIDs:   []string{"cust-123"},
		CustomerData:  map[string]any{"app_id": "app-9", "env": "prod"},
		Image:         Image{Repository: "customer-123", Name: "app", Tag: "v1.2.0", Digest: "sha256:abc", MediaType: "application/vnd.oci.image.index.v1+json"},
		Options:       ScanOptions{Platforms: []string{"npm", "jar"}, Severity: []string{"HIGH", "CRITICAL"}, MaxDBAge: time.Hour},
		Reference:     "harbor.local/customer-123/app@sha256:abc",
		State:         ScanDone,

		QueuedAt:    at,
		StartedAt:   &started,
		FinishedAt:  &finished,
		QueueWaitMS: 1000,
		ScanMS:      4000,
		TotalMS:     5000,

		Worker:       "worker-1",
		LeaseUntil:   &finished,
		Attempt:      1,
		Priority:     &priority,
		Error:        "an earlier failure",
		FailureClass: "trivy_timeout",

		Result: &ScanResult{
			Digest:             "sha256:abc",
			Platforms:          []string{"npm", "jar"},
			Severity:           []string{"HIGH", "CRITICAL"},
			ScannedPlatform:    "linux/amd64",
			TrivyVersion:       "0.74.0",
			ImagePlatformTypes: []string{"debian", "npm"},
			Summary:            map[string]int{"critical": 1, "high": 2},
			SummaryByPlatform:  map[string]map[string]int{"npm": {"critical": 1, "high": 2}},
			Truncated:          true,
			Report:             bson.M{"findings": bson.A{"stored by P7"}},
			ReportGridFSID:     &gridFSID,
		},
		DB:          &ScanDB{UpdatedAt: at.Add(-time.Hour), ManifestDigest: "sha256:db", Freshness: "ok"},
		ConfirmedAt: &finished,
	}

	t.Run("field names follow DEMAND section 10", func(t *testing.T) {
		assert.Equal(t, sorted("_id", "last_request_id", "requested_at", "customer_ids", "customer_data", "image",
			"options", "reference", "state", "queued_at", "started_at", "finished_at", "queue_wait_ms", "scan_ms", "total_ms",
			"worker", "lease_until", "attempt", "priority", "error", "failure_class", "result", "db", "confirmed_at"),
			keysOf(t, done))
		assert.Equal(t, sorted("repository", "name", "tag", "digest", "media_type"), keysOf(t, done.Image))
		assert.Equal(t, sorted("platforms", "severity", "max_db_age"), keysOf(t, done.Options))
		assert.Equal(t, sorted("digest", "platforms", "severity", "scanned_platform", "trivy_version", "image_platform_types",
			"summary", "summary_by_platform", "truncated", "report", "report_gridfs_id"), keysOf(t, done.Result))
		assert.Equal(t, sorted("updated_at", "manifest_digest", "freshness"), keysOf(t, done.DB))
	})

	t.Run("a first queued scan has no result and no times that are not known yet", func(t *testing.T) {
		queued := Scan{ID: "scan-2", State: ScanQueued, QueuedAt: at}

		keys := keysOf(t, queued)

		for _, absent := range []string{"last_request_id", "started_at", "finished_at", "lease_until", "worker", "error",
			"failure_class", "result", "db", "confirmed_at", "priority"} {
			assert.NotContains(t, keys, absent)
		}
		assert.Contains(t, keys, "queued_at")
	})

	t.Run("round trip", func(t *testing.T) {
		var decoded Scan
		roundTrip(t, done, &decoded)
		assert.Equal(t, done, decoded)
	})
}

func TestPlatform_BSON(t *testing.T) {
	platform := Platform{ID: "npm", FirstSeenAt: at, LastSeenAt: at.Add(time.Hour), SeenCount: 3, ExampleDigest: "sha256:abc"}

	assert.Equal(t, sorted("_id", "first_seen_at", "last_seen_at", "seen_count", "example_digest"), keysOf(t, platform))
	var decoded Platform
	roundTrip(t, platform, &decoded)
	assert.Equal(t, platform, decoded)
}

func sourceResult() dbmgr.SourceResult {
	return dbmgr.SourceResult{
		Source: "ghcr.io/aquasecurity/trivy-db:2|direct",
		Precheck: dbmgr.CheckResult{
			Source:    "ghcr.io/aquasecurity/trivy-db:2|direct",
			OK:        true,
			StartedAt: at,
			Duration:  1500 * time.Millisecond,
			Stages: []dbmgr.StageResult{
				{Stage: "dns", OK: true, Duration: 200 * time.Millisecond, Detail: "ghcr.io -> 140.82.121.34"},
				{Stage: "http", OK: true, Duration: 190 * time.Millisecond, FirstByte: 190 * time.Millisecond, Detail: "protocol=HTTP/2.0 status=401"},
			},
		},
		Answered:       true,
		ManifestDigest: "sha256:manifest",
		Installed:      true,
	}
}

func TestDBStateDocument_BSON(t *testing.T) {
	document := DBStateDocument{
		ID:         "scanner-1:db",
		InstanceID: "scanner-1",
		DB:         "db",
		UpdatedAt:  at,
		DBState: dbmgr.DBState{
			Mode:                   dbmgr.ModeNormal,
			ActiveSource:           "ghcr.io/aquasecurity/trivy-db:2|direct",
			ManifestDigest:         "sha256:manifest",
			LastUpstreamCheckAt:    at,
			LastConfirmedCurrentAt: at,
			NewerAvailable:         false,
			InstalledAt:            at,
			Metadata:               dbmgr.Metadata{Version: 2, UpdatedAt: at.Add(-time.Hour), NextUpdate: at.Add(time.Hour)},
			LastSources:            []dbmgr.SourceResult{sourceResult()},
		},
	}

	assert.Equal(t, sorted("_id", "instance_id", "db", "updated_at", "mode", "active_source", "manifest_digest", "last_upstream_check_at",
		"last_confirmed_current_at", "newer_available", "installed_at", "metadata", "last_sources"), keysOf(t, document))
	assert.Equal(t, sorted("version", "next_update", "updated_at", "downloaded_at"), keysOf(t, document.Metadata))
	assert.Equal(t, sorted("source", "precheck", "answered", "manifest_digest", "installed"), keysOf(t, sourceResult()))
	assert.Equal(t, sorted("source", "ok", "started_at", "duration", "stages"), keysOf(t, sourceResult().Precheck))
	assert.Equal(t, sorted("stage", "ok", "duration", "first_byte", "detail"), keysOf(t, sourceResult().Precheck.Stages[1]))

	var decoded DBStateDocument
	roundTrip(t, document, &decoded)
	assert.Equal(t, document, decoded)
}

func TestDBCheck_BSON(t *testing.T) {
	check := DBCheck{ID: DBCheckID("scanner-1", "db", at, "mirror|direct"), InstanceID: "scanner-1", DB: "db", At: at, SourceResult: sourceResult()}

	keys := keysOf(t, check)

	assert.Equal(t, sorted("_id", "instance_id", "db", "at", "source", "precheck", "answered", "manifest_digest", "installed"), keys)
	assert.Equal(t, "scanner-1:db:2026-10-15T10:00:00.123Z:mirror|direct", check.ID)
	var decoded DBCheck
	roundTrip(t, check, &decoded)
	assert.Equal(t, check, decoded)
}
