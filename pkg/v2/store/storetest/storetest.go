// Package storetest holds the contract tests of the store repositories. They run
// against the memory fakes (unit tests) and against MongoDB (integration tests),
// so the fakes behave like the real thing.
package storetest

import (
	"context"
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

func scan(id, requestID, digest, state string, finishedAt *time.Time) store.Scan {
	return store.Scan{
		ID:          id,
		RequestID:   requestID,
		RequestedAt: base,
		CustomerIDs: []string{"cust-1"},
		Image:       store.Image{Repository: "customer-1", Name: "app", Tag: "v1", Digest: digest},
		Options:     store.ScanOptions{Platforms: []string{"npm"}, Severity: []string{"HIGH", "CRITICAL"}},
		State:       state,
		QueuedAt:    base,
		FinishedAt:  finishedAt,
	}
}

// ScanRepository checks the ScanRepository contract. newRepository returns an
// empty repository each time.
func ScanRepository(t *testing.T, newRepository func(t *testing.T) store.ScanRepository) {
	ctx := context.Background()

	t.Run("create and get", func(t *testing.T) {
		repository := newRepository(t)
		created := scan("scan-1", "req-1", "sha256:a", store.ScanQueued, nil)
		require.NoError(t, repository.Create(ctx, created))

		got, err := repository.Get(ctx, "scan-1")
		require.NoError(t, err)
		assert.Equal(t, created, got)

		byRequest, err := repository.GetByRequestID(ctx, "req-1")
		require.NoError(t, err)
		assert.Equal(t, created, byRequest)
	})

	t.Run("not found", func(t *testing.T) {
		repository := newRepository(t)

		_, err := repository.Get(ctx, "missing")
		assert.ErrorIs(t, err, store.ErrNotFound)
		_, err = repository.GetByRequestID(ctx, "missing")
		assert.ErrorIs(t, err, store.ErrNotFound)
		_, err = repository.LastDone(ctx, "sha256:missing")
		assert.ErrorIs(t, err, store.ErrNotFound)
	})

	t.Run("request_id is unique, scans without one never collide", func(t *testing.T) {
		repository := newRepository(t)
		require.NoError(t, repository.Create(ctx, scan("scan-1", "req-1", "sha256:a", store.ScanQueued, nil)))
		require.NoError(t, repository.Create(ctx, scan("scan-2", "", "sha256:a", store.ScanQueued, nil)))
		require.NoError(t, repository.Create(ctx, scan("scan-3", "", "sha256:a", store.ScanQueued, nil)))

		err := repository.Create(ctx, scan("scan-4", "req-1", "sha256:b", store.ScanQueued, nil))
		assert.ErrorIs(t, err, store.ErrDuplicateRequestID)

		err = repository.Create(ctx, scan("scan-1", "req-9", "sha256:a", store.ScanQueued, nil))
		assert.Error(t, err, "the same scan id twice")
		assert.NotErrorIs(t, err, store.ErrDuplicateRequestID)
	})

	t.Run("last done is the newest finished successful scan of the digest", func(t *testing.T) {
		repository := newRepository(t)
		require.NoError(t, repository.Create(ctx, scan("old", "", "sha256:a", store.ScanDone, at(1))))
		require.NoError(t, repository.Create(ctx, scan("newest", "", "sha256:a", store.ScanDone, at(3))))
		require.NoError(t, repository.Create(ctx, scan("middle", "", "sha256:a", store.ScanDone, at(2))))
		require.NoError(t, repository.Create(ctx, scan("failed-later", "", "sha256:a", store.ScanFailed, at(4))))
		require.NoError(t, repository.Create(ctx, scan("queued", "", "sha256:a", store.ScanQueued, nil)))
		require.NoError(t, repository.Create(ctx, scan("other-digest", "", "sha256:b", store.ScanDone, at(5))))

		last, err := repository.LastDone(ctx, "sha256:a")

		require.NoError(t, err)
		assert.Equal(t, "newest", last.ID)
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
		return store.DBCheck{DB: db, At: *at(minutes), SourceResult: dbmgr.SourceResult{
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
}

// ReportStore checks the ReportStore contract. newStore returns an empty store
// that keeps reports up to limit BSON bytes inline.
func ReportStore(t *testing.T, newStore func(t *testing.T, limit int) store.ReportStore) {
	ctx := context.Background()
	report := bson.M{"vulnerabilities": strings.Repeat("CVE-2026-0001 ", 50)}

	t.Run("small report stays inline", func(t *testing.T) {
		reports := newStore(t, 10_000)
		scan := scan("scan-1", "", "sha256:a", store.ScanDone, at(1))

		require.NoError(t, reports.Attach(ctx, &scan, report))

		assert.Equal(t, report, scan.Report)
		assert.Nil(t, scan.ReportGridFSID)
		loaded, err := reports.Load(ctx, scan)
		require.NoError(t, err)
		assert.Equal(t, report, loaded)
	})

	t.Run("large report goes to GridFS", func(t *testing.T) {
		reports := newStore(t, 100)
		scan := scan("scan-1", "", "sha256:a", store.ScanDone, at(1))

		require.NoError(t, reports.Attach(ctx, &scan, report))

		assert.Nil(t, scan.Report)
		require.NotNil(t, scan.ReportGridFSID)
		loaded, err := reports.Load(ctx, scan)
		require.NoError(t, err)
		assert.Equal(t, report, loaded)
	})

	t.Run("scan without report", func(t *testing.T) {
		reports := newStore(t, 100)

		loaded, err := reports.Load(ctx, scan("scan-1", "", "sha256:a", store.ScanQueued, nil))

		require.NoError(t, err)
		assert.Nil(t, loaded)
	})

	t.Run("unknown GridFS file", func(t *testing.T) {
		reports := newStore(t, 100)
		missing := bson.NewObjectID()
		withMissingFile := scan("scan-1", "", "sha256:a", store.ScanDone, at(1))
		withMissingFile.ReportGridFSID = &missing

		_, err := reports.Load(ctx, withMissingFile)

		assert.Error(t, err)
	})
}
