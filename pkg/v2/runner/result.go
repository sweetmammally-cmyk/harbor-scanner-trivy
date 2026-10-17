package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// MaxPlatforms is the most platforms one request may ask for.
const MaxPlatforms = 20

// Severities are Trivy's severities, the only values a request may use.
var Severities = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// platformPattern is a valid platform (a Trivy result type such as npm or debian).
var platformPattern = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// ErrInvalidOptions is returned for invalid platforms or severities (400).
var ErrInvalidOptions = errors.New("invalid scan options")

// ValidateOptions checks the requested platforms and severities (DEMAND section 6.2).
func ValidateOptions(platforms, severities []string) error {
	if len(platforms) == 0 {
		return fmt.Errorf("%w: platforms is required", ErrInvalidOptions)
	}
	if len(platforms) > MaxPlatforms {
		return fmt.Errorf("%w: at most %d platforms", ErrInvalidOptions, MaxPlatforms)
	}
	for _, platform := range platforms {
		if !platformPattern.MatchString(platform) {
			return fmt.Errorf("%w: platform %q must be lowercase letters, digits, '-' or '_'", ErrInvalidOptions, platform)
		}
	}
	for _, severity := range severities {
		if !slices.Contains(Severities, severity) {
			return fmt.Errorf("%w: severity %q must be one of %s", ErrInvalidOptions, severity, strings.Join(Severities, ", "))
		}
	}
	return nil
}

// Finding is one stored finding. Descriptions, references and package lists
// are not kept.
type Finding struct {
	ID               string `json:"id" bson:"id"`
	Package          string `json:"package" bson:"package"`
	InstalledVersion string `json:"installed_version" bson:"installed_version"`
	FixedVersion     string `json:"fixed_version,omitempty" bson:"fixed_version,omitempty"`
	Severity         string `json:"severity" bson:"severity"`
	Title            string `json:"title,omitempty" bson:"title,omitempty"`
	PrimaryURL       string `json:"primary_url,omitempty" bson:"primary_url,omitempty"`
	Status           string `json:"status,omitempty" bson:"status,omitempty"`
	Target           string `json:"target" bson:"target"`
	Type             string `json:"type" bson:"type"`
}

// Result is what one scan keeps from Trivy's output.
type Result struct {
	// PlatformsFound and PlatformsNotFound split the requested platforms by
	// whether the image has them. A requested platform that is not in the image
	// must never look like a clean result.
	PlatformsFound    []string
	PlatformsNotFound []string
	// ImagePlatforms are all result types in the image, requested or not.
	ImagePlatforms   []string
	HasMorePlatforms bool
	// Summary counts the findings of the requested platforms at every severity,
	// by lowercase severity name. SummaryByPlatform splits it by platform, for
	// the requested platforms that the image has.
	Summary           map[string]int
	SummaryByPlatform map[string]map[string]int
	// Findings are those of the requested platforms and severities, at most
	// maxFindings; Truncated is set when more were left out.
	Findings  []Finding
	Truncated bool
}

// trivyResult is the part of a Trivy result we read.
type trivyResult struct {
	Target          string `json:"Target"`
	Type            string `json:"Type"`
	Vulnerabilities []struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		FixedVersion     string `json:"FixedVersion"`
		Severity         string `json:"Severity"`
		Title            string `json:"Title"`
		PrimaryURL       string `json:"PrimaryURL"`
		Status           string `json:"Status"`
	} `json:"Vulnerabilities"`
}

// parseResult reads Trivy's JSON output one result at a time and keeps what the
// request asked for: platforms (matched case-insensitively against the result
// type) and severities. Malformed output is an output_invalid ScanError.
func parseResult(output io.Reader, platforms, severities []string, maxFindings int) (Result, error) {
	result := Result{Summary: zeroSummary(), SummaryByPlatform: map[string]map[string]int{}}
	imageTypes := map[string]bool{}

	decoder := json.NewDecoder(output)
	if err := expectDelim(decoder, '{'); err != nil {
		return Result{}, invalidOutput(err)
	}
	schemaVersion := 0
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return Result{}, invalidOutput(err)
		}
		switch key {
		case "SchemaVersion":
			if err = decoder.Decode(&schemaVersion); err != nil {
				return Result{}, invalidOutput(err)
			}
		case "Results":
			if err = expectDelim(decoder, '['); err != nil {
				return Result{}, invalidOutput(err)
			}
			for decoder.More() {
				var trivyResult trivyResult
				if err = decoder.Decode(&trivyResult); err != nil {
					return Result{}, invalidOutput(err)
				}
				resultType := strings.ToLower(trivyResult.Type)
				if resultType != "" {
					imageTypes[resultType] = true
				}
				if !slices.Contains(platforms, resultType) {
					continue
				}
				if result.SummaryByPlatform[resultType] == nil {
					result.SummaryByPlatform[resultType] = zeroSummary()
				}
				for _, vulnerability := range trivyResult.Vulnerabilities {
					result.Summary[strings.ToLower(vulnerability.Severity)]++
					result.SummaryByPlatform[resultType][strings.ToLower(vulnerability.Severity)]++
					if !slices.Contains(severities, vulnerability.Severity) {
						continue
					}
					if len(result.Findings) == maxFindings {
						result.Truncated = true
						continue
					}
					result.Findings = append(result.Findings, Finding{
						ID:               vulnerability.VulnerabilityID,
						Package:          vulnerability.PkgName,
						InstalledVersion: vulnerability.InstalledVersion,
						FixedVersion:     vulnerability.FixedVersion,
						Severity:         vulnerability.Severity,
						Title:            vulnerability.Title,
						PrimaryURL:       vulnerability.PrimaryURL,
						Status:           vulnerability.Status,
						Target:           trivyResult.Target,
						Type:             resultType,
					})
				}
			}
			if err = expectDelim(decoder, ']'); err != nil {
				return Result{}, invalidOutput(err)
			}
		default:
			var skip json.RawMessage
			if err = decoder.Decode(&skip); err != nil {
				return Result{}, invalidOutput(err)
			}
		}
	}
	if err := expectDelim(decoder, '}'); err != nil {
		return Result{}, invalidOutput(err)
	}
	if schemaVersion != 2 {
		return Result{}, invalidOutput(fmt.Errorf("unsupported SchemaVersion %d, expected 2", schemaVersion))
	}

	for _, platform := range platforms {
		if imageTypes[platform] {
			result.PlatformsFound = append(result.PlatformsFound, platform)
		} else {
			result.PlatformsNotFound = append(result.PlatformsNotFound, platform)
		}
	}
	for imageType := range imageTypes {
		result.ImagePlatforms = append(result.ImagePlatforms, imageType)
		if !slices.Contains(platforms, imageType) {
			result.HasMorePlatforms = true
		}
	}
	sort.Strings(result.ImagePlatforms)
	return result, nil
}

// zeroSummary has every severity, by lowercase name, at 0.
func zeroSummary() map[string]int {
	summary := map[string]int{}
	for _, severity := range Severities {
		summary[strings.ToLower(severity)] = 0
	}
	return summary
}

func expectDelim(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("expected %q, got %v", want, token)
	}
	return nil
}

func invalidOutput(err error) error {
	return &ScanError{Class: FailureOutputInvalid, Detail: "reading Trivy's JSON output: " + err.Error()}
}
