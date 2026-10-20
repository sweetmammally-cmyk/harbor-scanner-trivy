package queue

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func TestServes(t *testing.T) {
	dbTime := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	stored := store.Scan{
		Result: &store.ScanResult{Digest: "sha256:a", Platforms: []string{"jar", "npm"}, Severity: []string{"CRITICAL", "HIGH", "MEDIUM"},
			ScannedPlatform: "linux/amd64", TrivyVersion: "0.74.0"},
		DB: &store.ScanDB{UpdatedAt: dbTime},
	}
	want := func() Want {
		return Want{Digest: "sha256:a", ScannedPlatform: "linux/amd64", TrivyVersion: "0.74.0", DBUpdatedAt: dbTime,
			Options: store.ScanOptions{Platforms: []string{"npm"}, Severity: []string{"HIGH"}}}
	}

	assert.True(t, Serves(stored, want()), "a narrower request with the same DB")
	// metadata.json has nanoseconds; MongoDB gives the stored time back in milliseconds.
	nanos := want()
	nanos.DBUpdatedAt = dbTime.Add(36595599 * time.Nanosecond)
	fromMongo := stored
	fromMongo.DB = &store.ScanDB{UpdatedAt: nanos.DBUpdatedAt.Truncate(time.Millisecond)}
	assert.True(t, Serves(fromMongo, nanos), "the same DB, stored in milliseconds, installed in nanoseconds")
	older := want()
	older.DBUpdatedAt = dbTime.Add(-time.Hour)
	assert.True(t, Serves(stored, older), "the result's DB is newer than the installed one")

	for name, change := range map[string]func(*Want){
		"another digest":           func(w *Want) { w.Digest = "sha256:b" },
		"another scanned platform": func(w *Want) { w.ScannedPlatform = "linux/arm64" },
		"another Trivy version":    func(w *Want) { w.TrivyVersion = "0.75.0" },
		"a platform not scanned":   func(w *Want) { w.Options.Platforms = []string{"npm", "pip"} },
		"a severity not stored":    func(w *Want) { w.Options.Severity = []string{"LOW"} },
		"a newer installed DB":     func(w *Want) { w.DBUpdatedAt = dbTime.Add(time.Second) },
		"an unknown installed DB":  func(w *Want) { w.DBUpdatedAt = time.Time{} },
	} {
		w := want()
		change(&w)
		assert.False(t, Serves(stored, w), name)
	}
	assert.False(t, Serves(store.Scan{}, want()), "no result yet")
}
