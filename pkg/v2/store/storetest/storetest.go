// Package storetest holds the contract tests of the store repositories. They run
// against the memory fakes (unit tests) and against MongoDB (integration tests),
// so the fakes behave like the real thing.
package storetest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// MongoDB stores times in milliseconds and UTC, so the tests use such times.
var base = time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)

func at(minutes int) *time.Time {
	t := base.Add(time.Duration(minutes) * time.Minute)
	return &t
}

func scan(id, digest, state string) store.Scan {
	return store.Scan{
		ID:          id,
		RequestedAt: base,
		CustomerIDs: []string{"cust-1"},
		Image:       store.Image{Repository: "customer-1", Name: "app", Tag: "v1", Digest: digest},
		Options:     store.ScanOptions{Platforms: []string{"npm"}, Severity: []string{"HIGH", "CRITICAL"}},
		State:       state,
		QueuedAt:    base,
	}
}

// withResult is a done scan with a result (and no report yet).
func withResult(id string) store.Scan {
	done := scan(id, "sha256:a", store.ScanDone)
	done.FinishedAt = at(1)
	done.Result = &store.ScanResult{Digest: "sha256:a", Platforms: []string{"npm"}, Severity: []string{"HIGH", "CRITICAL"}}
	return done
}

// ScanRepository checks the ScanRepository contract. newRepository returns an
// empty repository each time.
func ScanRepository(t *testing.T, newRepository func(t *testing.T) store.ScanRepository) {
	ctx := context.Background()

	t.Run("create and get", func(t *testing.T) {
		repository := newRepository(t)
		created := scan("scan-1", "sha256:a", store.ScanQueued)
		created.LastRequestID = "req-1"
		require.NoError(t, repository.Create(ctx, created))

		got, err := repository.Get(ctx, "scan-1")
		require.NoError(t, err)
		assert.Equal(t, created, got)
	})

	t.Run("not found", func(t *testing.T) {
		repository := newRepository(t)

		_, err := repository.Get(ctx, "missing")
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("one document per id; request ids are not unique", func(t *testing.T) {
		repository := newRepository(t)
		first := scan("scan-1", "sha256:a", store.ScanQueued)
		first.LastRequestID = "req-1"
		require.NoError(t, repository.Create(ctx, first))
		other := scan("scan-2", "sha256:a", store.ScanQueued)
		other.LastRequestID = "req-1"
		require.NoError(t, repository.Create(ctx, other))

		assert.Error(t, repository.Create(ctx, scan("scan-1", "sha256:b", store.ScanQueued)), "the same scan id twice")
	})
}

// PlatformRepository checks the PlatformRepository contract.
func PlatformRepository(t *testing.T, newRepository func(t *testing.T) store.PlatformRepository) {
	ctx := context.Background()

	t.Run("first sighting creates, later sightings count", func(t *testing.T) {
		repository := newRepository(t)
		require.NoError(t, repository.Seen(ctx, []string{"npm", "debian"}, "sha256:first", *at(1)))
		require.NoError(t, repository.Seen(ctx, []string{"npm"}, "sha256:second", *at(2)))

		platforms, err := repository.List(ctx)

		require.NoError(t, err)
		assert.Equal(t, []store.Platform{
			{ID: "debian", FirstSeenAt: *at(1), LastSeenAt: *at(1), SeenCount: 1, ExampleDigest: "sha256:first"},
			{ID: "npm", FirstSeenAt: *at(1), LastSeenAt: *at(2), SeenCount: 2, ExampleDigest: "sha256:first"},
		}, platforms)
	})

	t.Run("empty", func(t *testing.T) {
		repository := newRepository(t)
		require.NoError(t, repository.Seen(ctx, nil, "sha256:x", base))

		platforms, err := repository.List(ctx)

		require.NoError(t, err)
		assert.Empty(t, platforms)
	})
}

// DBCheckRepository checks the DBCheckRepository contract.
func DBCheckRepository(t *testing.T, newRepository func(t *testing.T) store.DBCheckRepository) {
	ctx := context.Background()
	check := func(db string, minutes int, class string) store.DBCheck {
		return store.DBCheck{ID: store.DBCheckID("scanner-1", db, *at(minutes), "mirror|direct"), DB: db, At: *at(minutes), SourceResult: dbmgr.SourceResult{
			Source:       "mirror|direct",
			FailureClass: class,
			Precheck:     dbmgr.CheckResult{Source: "mirror|direct", StartedAt: *at(minutes), Duration: time.Second},
		}}
	}

	t.Run("recent checks of one DB, newest first, limited", func(t *testing.T) {
		repository := newRepository(t)
		require.NoError(t, repository.Add(ctx, []store.DBCheck{check("db", 1, "tls_reset"), check("db", 3, "")}))
		require.NoError(t, repository.Add(ctx, []store.DBCheck{check("java-db", 4, ""), check("db", 2, "tcp_timeout")}))
		require.NoError(t, repository.Add(ctx, nil))

		recent, err := repository.Recent(ctx, "db", 2)

		require.NoError(t, err)
		require.Len(t, recent, 2)
		assert.Equal(t, *at(3), recent[0].At)
		assert.Equal(t, "", recent[0].FailureClass)
		assert.Equal(t, *at(2), recent[1].At)
		assert.Equal(t, "tcp_timeout", recent[1].FailureClass)
		assert.Equal(t, time.Second, recent[1].Precheck.Duration)

		java, err := repository.Recent(ctx, "java-db", 10)
		require.NoError(t, err)
		assert.Len(t, java, 1)
	})

	t.Run("adding the same rows twice keeps one of each", func(t *testing.T) {
		repository := newRepository(t)
		rows := []store.DBCheck{check("db", 1, "tls_reset"), check("db", 2, "")}
		require.NoError(t, repository.Add(ctx, rows))

		rows[0].FailureClass = "tls_timeout" // the second write replaces the first
		require.NoError(t, repository.Add(ctx, rows))

		recent, err := repository.Recent(ctx, "db", 10)
		require.NoError(t, err)
		require.Len(t, recent, 2)
		assert.Equal(t, "tls_timeout", recent[1].FailureClass)
	})
}

// ReportStore checks the ReportStore contract. newStore returns an empty store
// with the given inline limit.
func ReportStore(t *testing.T, newStore func(t *testing.T, limit int) store.ReportStore) {
	ctx := context.Background()
	report := bson.M{"findings": strings.Repeat("CVE-2026-0001 ", 50)}

	t.Run("small report stays inline", func(t *testing.T) {
		reports := newStore(t, 10_000)
		scan := withResult("scan-1")

		require.NoError(t, reports.Attach(ctx, &scan, report))

		assert.Equal(t, report, scan.Result.Report)
		assert.Nil(t, scan.Result.ReportGridFSID)
		loaded, err := reports.Load(ctx, scan)
		require.NoError(t, err)
		assert.Equal(t, report, loaded)
	})

	t.Run("large report goes to GridFS", func(t *testing.T) {
		reports := newStore(t, 100)
		scan := withResult("scan-1")

		require.NoError(t, reports.Attach(ctx, &scan, report))

		assert.Nil(t, scan.Result.Report)
		require.NotNil(t, scan.Result.ReportGridFSID)
		loaded, err := reports.Load(ctx, scan)
		require.NoError(t, err)
		assert.Equal(t, report, loaded)
	})

	t.Run("scan without result", func(t *testing.T) {
		reports := newStore(t, 100)

		loaded, err := reports.Load(ctx, scan("scan-1", "sha256:a", store.ScanQueued))

		require.NoError(t, err)
		assert.Nil(t, loaded)
	})

	t.Run("save with report: a failed save deletes the new file and keeps the previous one", func(t *testing.T) {
		reports := newStore(t, 100)
		previous := withResult("scan-1")
		require.NoError(t, store.SaveWithReport(ctx, reports, previous, report, func(ctx context.Context, scan store.Scan) error {
			previous = scan
			return nil
		}))
		var attempted store.Scan
		saveErr := errors.New("mongo write failed")

		err := store.SaveWithReport(ctx, reports, withResult("scan-1"), report,
			func(ctx context.Context, scan store.Scan) error {
				attempted = scan
				return saveErr
			})

		assert.ErrorIs(t, err, saveErr)
		require.NotNil(t, attempted.Result.ReportGridFSID, "the file was uploaded before the save")
		_, err = reports.Load(ctx, attempted)
		assert.Error(t, err, "and deleted after the failed save")
		loaded, err := reports.Load(ctx, previous)
		require.NoError(t, err, "the last good result keeps its file")
		assert.Equal(t, report, loaded)
	})

	t.Run("save with report: a successful save deletes the previous result's file", func(t *testing.T) {
		reports := newStore(t, 100)
		var previous, saved store.Scan
		require.NoError(t, store.SaveWithReport(ctx, reports, withResult("scan-1"), report, func(ctx context.Context, scan store.Scan) error {
			previous = scan
			return nil
		}))
		other := withResult("scan-2")
		require.NoError(t, store.SaveWithReport(ctx, reports, other, report, func(ctx context.Context, scan store.Scan) error {
			other = scan
			return nil
		}))

		err := store.SaveWithReport(ctx, reports, withResult("scan-1"), report,
			func(ctx context.Context, scan store.Scan) error {
				saved = scan
				return nil
			})

		require.NoError(t, err)
		loaded, err := reports.Load(ctx, saved)
		require.NoError(t, err)
		assert.Equal(t, report, loaded)
		_, err = reports.Load(ctx, previous)
		assert.Error(t, err, "the previous result's file is gone")
		_, err = reports.Load(ctx, other)
		assert.NoError(t, err, "files of other scan ids are left alone")
	})

	t.Run("save with report: a small report has no file", func(t *testing.T) {
		reports := newStore(t, 10_000)

		err := store.SaveWithReport(ctx, reports, withResult("scan-1"), report,
			func(ctx context.Context, scan store.Scan) error {
				assert.Nil(t, scan.Result.ReportGridFSID)
				assert.Equal(t, report, scan.Result.Report)
				return nil
			})

		assert.NoError(t, err)
	})

	t.Run("unknown GridFS file", func(t *testing.T) {
		reports := newStore(t, 100)
		missing := bson.NewObjectID()
		withMissingFile := withResult("scan-1")
		withMissingFile.Result.ReportGridFSID = &missing

		_, err := reports.Load(ctx, withMissingFile)

		assert.Error(t, err)
	})
}
