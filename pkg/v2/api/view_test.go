package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func TestNewResultView(t *testing.T) {
	scan := store.Scan{
		ID:    "id-1",
		State: store.ScanDone,
		Image: store.Image{Repository: "project", Name: "app", Tag: "v1", Digest: "sha256:new"},
		Result: &store.ScanResult{
			Digest:             "sha256:scanned",
			Platforms:          []string{"jar", "npm", "pip"},
			Severity:           []string{"CRITICAL", "HIGH", "LOW"},
			ImagePlatformTypes: []string{"debian", "jar", "npm"},
			SummaryByPlatform: map[string]map[string]int{
				"npm": {"critical": 1, "high": 2, "low": 3},
				"jar": {"high": 5},
			},
		},
		QueueWaitMS: 1, ScanMS: 2, TotalMS: 3,
	}
	report := bson.M{"findings": []runner.Finding{
		{ID: "CVE-1", Type: "npm", Severity: "HIGH"},
		{ID: "CVE-2", Type: "npm", Severity: "LOW"},
		{ID: "CVE-3", Type: "jar", Severity: "HIGH"},
		{ID: "CVE-4", Type: "npm", Severity: "CRITICAL"},
	}}

	view, err := newResultView(scan, report, []string{"npm", "pip"}, []string{"CRITICAL", "HIGH"}, dbBlock{Freshness: "ok"})

	require.NoError(t, err)
	assert.Equal(t, "sha256:scanned", view.Image.Digest, "the digest of the result")
	assert.Equal(t, []string{"npm"}, view.PlatformsFound)
	assert.Equal(t, []string{"pip"}, view.PlatformsNotFound, "scanned, but not in the image")
	assert.True(t, view.HasMorePlatforms, "debian and jar")
	assert.Equal(t, map[string]int{"critical": 1, "high": 2, "medium": 0, "low": 3, "unknown": 0}, view.Summary,
		"counts of the requested platforms only, at every severity")
	var ids []string
	for _, finding := range view.Vulnerabilities {
		ids = append(ids, finding.ID)
	}
	assert.Equal(t, []string{"CVE-1", "CVE-4"}, ids, "findings of the requested platforms and severities")
	assert.Equal(t, timingView{QueueWaitMS: 1, ScanMS: 2, TotalMS: 3}, view.Timing)
	assert.False(t, view.Cached)

	all, err := newResultView(scan, nil, []string{"debian", "jar", "npm"}, []string{"HIGH"}, dbBlock{})
	require.NoError(t, err)
	assert.False(t, all.HasMorePlatforms)
	assert.Empty(t, all.PlatformsNotFound)
	assert.NotNil(t, all.Vulnerabilities, "an empty list, not null")
}
