package api

import (
	"fmt"
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// resultView is a stored result filtered to a request (DEMAND section 5.2).
type resultView struct {
	ScanID string `json:"scan_id"`
	State  string `json:"state"`
	// Cached and DBUnchanged are set only on POST hits; they are never stored.
	Cached             bool             `json:"cached,omitempty"`
	DBUnchanged        bool             `json:"db_unchanged,omitempty"`
	Image              imageView        `json:"image"`
	DB                 dbBlock          `json:"db"`
	PlatformsRequested []string         `json:"platforms_requested"`
	PlatformsFound     []string         `json:"platforms_found"`
	PlatformsNotFound  []string         `json:"platforms_not_found"`
	HasMorePlatforms   bool             `json:"has_more_platforms"`
	Severity           []string         `json:"severity"`
	Summary            map[string]int   `json:"summary"`
	Truncated          bool             `json:"truncated"`
	Vulnerabilities    []runner.Finding `json:"vulnerabilities"`
	Timing             timingView       `json:"timing"`
	CustomerIDs        []string         `json:"customer_ids"`
	CustomerData       map[string]any   `json:"customer_data,omitempty"`
	RequestID          string           `json:"request_id,omitempty"`
}

type imageView struct {
	Repository string `json:"repository"`
	Name       string `json:"name"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
}

type timingView struct {
	QueueWaitMS int64 `json:"queue_wait_ms"`
	ScanMS      int64 `json:"scan_ms"`
	TotalMS     int64 `json:"total_ms"`
}

// storedFindings is the stored report.
type storedFindings struct {
	Findings []runner.Finding `bson:"findings"`
}

// newResultView filters the scan's result and report to the platforms and
// severities asked for, which the stored scope covers: the findings of those
// platforms and severities, the summary summed over those platforms only, and
// the platforms found, not found and "more" computed for the request.
func newResultView(scan store.Scan, report bson.M, platforms, severity []string, db dbBlock) (resultView, error) {
	result := scan.Result
	view := resultView{
		ScanID:             scan.ID,
		State:              scan.State,
		Image:              imageView{Repository: scan.Image.Repository, Name: scan.Image.Name, Tag: scan.Image.Tag, Digest: result.Digest},
		DB:                 db,
		PlatformsRequested: platforms,
		PlatformsFound:     []string{},
		PlatformsNotFound:  []string{},
		Severity:           severity,
		Summary:            map[string]int{},
		Truncated:          result.Truncated,
		Vulnerabilities:    []runner.Finding{},
		Timing:             timingView{QueueWaitMS: scan.QueueWaitMS, ScanMS: scan.ScanMS, TotalMS: scan.TotalMS},
		CustomerIDs:        scan.CustomerIDs,
		CustomerData:       scan.CustomerData,
		RequestID:          scan.LastRequestID,
	}

	for _, value := range runner.Severities {
		view.Summary[strings.ToLower(value)] = 0
	}
	for _, platform := range platforms {
		for value, count := range result.SummaryByPlatform[platform] {
			view.Summary[value] += count
		}
		if slices.Contains(result.ImagePlatformTypes, platform) {
			view.PlatformsFound = append(view.PlatformsFound, platform)
		} else {
			view.PlatformsNotFound = append(view.PlatformsNotFound, platform)
		}
	}
	for _, imageType := range result.ImagePlatformTypes {
		if !slices.Contains(platforms, imageType) {
			view.HasMorePlatforms = true
		}
	}

	if report != nil {
		data, err := bson.Marshal(report)
		if err != nil {
			return resultView{}, fmt.Errorf("encoding report of scan %s: %w", scan.ID, err)
		}
		var stored storedFindings
		if err = bson.Unmarshal(data, &stored); err != nil {
			return resultView{}, fmt.Errorf("decoding report of scan %s: %w", scan.ID, err)
		}
		for _, finding := range stored.Findings {
			if slices.Contains(platforms, finding.Type) && slices.Contains(severity, finding.Severity) {
				view.Vulnerabilities = append(view.Vulnerabilities, finding)
			}
		}
	}
	return view, nil
}
