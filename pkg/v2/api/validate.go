package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/registry"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// Request limits (DEMAND section 5.1).
const (
	maxCustomerIDs      = 100
	maxCustomerIDLength = 128
	maxCustomerData     = 64 << 10
	maxFutureSkew       = 5 * time.Minute
	minMaxDBAge         = time.Minute
	maxMaxDBAge         = 30 * 24 * time.Hour
)

// defaultSeverity is used when a request names no severity.
var defaultSeverity = []string{"CRITICAL", "HIGH"}

// scanRequest is the body of POST /api/v2/scans.
type scanRequest struct {
	RequestID    string         `json:"request_id"`
	RequestedAt  string         `json:"requested_at"`
	Image        imageRequest   `json:"image"`
	CustomerIDs  []string       `json:"customer_ids"`
	CustomerData map[string]any `json:"customer_data"`
	Platforms    []string       `json:"platforms"`
	Severity     []string       `json:"severity"`
	MaxDBAge     string         `json:"max_db_age"`
	Force        bool           `json:"force"`
}

type imageRequest struct {
	Repository string `json:"repository"`
	Name       string `json:"name"`
	Tag        string `json:"tag"`
}

// validate checks a scan request and returns it as a scan to enqueue (without
// digest and reference) with normalized options. now is the receive time.
func validate(request scanRequest, now time.Time, defaultMaxDBAge time.Duration) (store.Scan, error) {
	scan := store.Scan{ReceivedAt: now, CustomerData: request.CustomerData}

	if request.RequestID != "" && !requestIDPattern.MatchString(request.RequestID) {
		return store.Scan{}, errors.New("request_id must be 1-128 characters of A-Za-z0-9._:-")
	}
	scan.LastRequestID = request.RequestID

	if request.RequestedAt != "" {
		requestedAt, err := time.Parse(time.RFC3339, request.RequestedAt)
		if err != nil {
			return store.Scan{}, errors.New("requested_at must be an RFC 3339 time")
		}
		if requestedAt.After(now.Add(maxFutureSkew)) {
			return store.Scan{}, errors.New("requested_at is more than 5 minutes in the future")
		}
		scan.RequestedAt = requestedAt
	}

	image := registry.Image{Repository: request.Image.Repository, Name: request.Image.Name, Tag: request.Image.Tag}
	if err := registry.ValidateImage(image); err != nil {
		return store.Scan{}, err
	}
	scan.Image = store.Image{Repository: image.Repository, Name: image.Name, Tag: image.Tag}

	if len(request.CustomerIDs) == 0 || len(request.CustomerIDs) > maxCustomerIDs {
		return store.Scan{}, fmt.Errorf("customer_ids must have 1 to %d entries", maxCustomerIDs)
	}
	for _, id := range request.CustomerIDs {
		if id == "" || len(id) > maxCustomerIDLength {
			return store.Scan{}, fmt.Errorf("each customer_id must be 1 to %d characters", maxCustomerIDLength)
		}
	}
	scan.CustomerIDs = request.CustomerIDs

	if request.CustomerData != nil {
		data, err := json.Marshal(request.CustomerData)
		if err != nil || len(data) > maxCustomerData {
			return store.Scan{}, fmt.Errorf("customer_data must be a JSON object of at most %d bytes", maxCustomerData)
		}
	}

	platforms, severity, err := normalizeOptions(request.Platforms, request.Severity)
	if err != nil {
		return store.Scan{}, err
	}
	if len(platforms) == 0 {
		return store.Scan{}, errors.New("platforms is required")
	}
	if len(severity) == 0 {
		severity = defaultSeverity
	}
	scan.Options = store.ScanOptions{Platforms: platforms, Severity: severity, MaxDBAge: defaultMaxDBAge}

	if request.MaxDBAge != "" {
		maxDBAge, err := config.ParseDuration(request.MaxDBAge)
		if err != nil || maxDBAge < minMaxDBAge || maxDBAge > maxMaxDBAge {
			return store.Scan{}, errors.New("max_db_age must be a duration between 1m and 30d")
		}
		scan.Options.MaxDBAge = maxDBAge
	}
	return scan, nil
}

// normalizeOptions lowercases the platforms and uppercases the severities,
// removes duplicates, sorts both and checks them. Empty lists stay empty.
func normalizeOptions(platforms, severity []string) ([]string, []string, error) {
	var normalizedPlatforms, normalizedSeverity []string
	for _, platform := range platforms {
		normalizedPlatforms = append(normalizedPlatforms, strings.ToLower(platform))
	}
	for _, value := range severity {
		normalizedSeverity = append(normalizedSeverity, strings.ToUpper(value))
	}
	slices.Sort(normalizedPlatforms)
	normalizedPlatforms = slices.Compact(normalizedPlatforms)
	slices.Sort(normalizedSeverity)
	normalizedSeverity = slices.Compact(normalizedSeverity)

	for _, value := range normalizedSeverity {
		if !slices.Contains(runner.Severities, value) {
			return nil, nil, fmt.Errorf("severity %q must be one of %s", value, strings.Join(runner.Severities, ", "))
		}
	}
	if len(normalizedPlatforms) > 0 {
		if err := runner.ValidateOptions(normalizedPlatforms, normalizedSeverity); err != nil {
			return nil, nil, err
		}
	}
	return normalizedPlatforms, normalizedSeverity, nil
}
