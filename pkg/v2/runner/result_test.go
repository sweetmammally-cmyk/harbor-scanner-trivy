package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture is real Trivy 0.74.0 output for node:22-alpine3.20, trimmed: alpine
// (CRITICAL, HIGH, HIGH, MEDIUM, LOW), node-pkg (HIGH, MEDIUM, LOW), and a pip
// result without findings.
const fixture = "testdata/node-alpine.json"

func parseFixture(t *testing.T, platforms, severities []string, maxFindings int) Result {
	t.Helper()
	file, err := os.Open(fixture)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	result, err := parseResult(file, platforms, severities, maxFindings)
	require.NoError(t, err)
	return result
}

func TestParseResult(t *testing.T) {
	highCritical := []string{"HIGH", "CRITICAL"}

	t.Run("requested platform and severities", func(t *testing.T) {
		result := parseFixture(t, []string{"alpine"}, highCritical, 100)

		assert.Equal(t, map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 1, "unknown": 0}, result.Summary,
			"counts cover every severity of the requested platform")
		require.Len(t, result.Findings, 3, "details only for the requested severities")
		for _, finding := range result.Findings {
			assert.Equal(t, "alpine", finding.Type)
			assert.Contains(t, highCritical, finding.Severity)
			assert.NotEmpty(t, finding.ID)
			assert.NotEmpty(t, finding.Package)
			assert.NotEmpty(t, finding.InstalledVersion)
			assert.Equal(t, "node:22-alpine3.20 (alpine 3.20.6)", finding.Target)
		}
		assert.Equal(t, map[string]map[string]int{"alpine": result.Summary}, result.SummaryByPlatform)
		assert.Equal(t, []string{"alpine"}, result.PlatformsFound)
		assert.Empty(t, result.PlatformsNotFound)
		assert.Equal(t, []string{"alpine", "node-pkg", "pip"}, result.ImagePlatforms)
		assert.True(t, result.HasMorePlatforms)
		assert.False(t, result.Truncated)
	})

	t.Run("the first finding carries the fields of the fixture", func(t *testing.T) {
		var raw struct {
			Results []struct {
				Vulnerabilities []map[string]any
			}
		}
		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &raw))
		first := raw.Results[0].Vulnerabilities[0]
		require.NotEmpty(t, first["Description"], "the fixture has a description, which must not be kept")

		finding := parseFixture(t, []string{"alpine"}, []string{"CRITICAL"}, 100).Findings[0]

		assert.Equal(t, first["VulnerabilityID"], finding.ID)
		assert.Equal(t, first["PkgName"], finding.Package)
		assert.Equal(t, first["InstalledVersion"], finding.InstalledVersion)
		assert.Equal(t, first["FixedVersion"], finding.FixedVersion)
		assert.Equal(t, first["Title"], finding.Title)
		assert.Equal(t, first["PrimaryURL"], finding.PrimaryURL)
		assert.Equal(t, first["Status"], finding.Status)
	})

	t.Run("a requested platform the image does not have is reported, not clean", func(t *testing.T) {
		result := parseFixture(t, []string{"npm"}, highCritical, 100)

		assert.Empty(t, result.PlatformsFound)
		assert.Equal(t, []string{"npm"}, result.PlatformsNotFound)
		assert.Empty(t, result.Findings)
		assert.True(t, result.HasMorePlatforms)
	})

	t.Run("a platform without findings is found and clean", func(t *testing.T) {
		result := parseFixture(t, []string{"pip"}, highCritical, 100)

		assert.Equal(t, []string{"pip"}, result.PlatformsFound)
		assert.Empty(t, result.Findings)
		assert.Equal(t, 0, result.Summary["high"])
	})

	t.Run("all platforms of the image requested: nothing more", func(t *testing.T) {
		result := parseFixture(t, []string{"alpine", "node-pkg", "pip", "npm"}, highCritical, 100)

		assert.False(t, result.HasMorePlatforms)
		assert.Equal(t, []string{"alpine", "node-pkg", "pip"}, result.PlatformsFound)
		assert.Equal(t, []string{"npm"}, result.PlatformsNotFound)
		assert.Len(t, result.Findings, 4)
		assert.Equal(t, 3, result.Summary["high"])
		assert.Len(t, result.SummaryByPlatform, 3, "one per requested platform that the image has")
		assert.NotContains(t, result.SummaryByPlatform, "npm")
		for severity, count := range result.Summary {
			total := 0
			for _, summary := range result.SummaryByPlatform {
				total += summary[severity]
			}
			assert.Equal(t, count, total, "the platforms add up to the summary for %s", severity)
		}
	})

	t.Run("more findings than the limit: truncated, counts complete", func(t *testing.T) {
		result := parseFixture(t, []string{"alpine", "node-pkg"}, Severities, 2)

		assert.Len(t, result.Findings, 2)
		assert.True(t, result.Truncated)
		assert.Equal(t, map[string]int{"critical": 1, "high": 3, "medium": 2, "low": 2, "unknown": 0}, result.Summary)
	})

	t.Run("result types are matched case-insensitively", func(t *testing.T) {
		output := `{"SchemaVersion":2,"Results":[{"Target":"t","Type":"Alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH"}]}]}`

		result, err := parseResult(strings.NewReader(output), []string{"alpine"}, []string{"HIGH"}, 10)

		require.NoError(t, err)
		assert.Equal(t, []string{"alpine"}, result.PlatformsFound)
		require.Len(t, result.Findings, 1)
		assert.Equal(t, "alpine", result.Findings[0].Type)
	})

	t.Run("many results are read one at a time", func(t *testing.T) {
		var output strings.Builder
		output.WriteString(`{"SchemaVersion":2,"Results":[`)
		for i := 0; i < 20000; i++ {
			if i > 0 {
				output.WriteString(",")
			}
			fmt.Fprintf(&output, `{"Target":"t%d","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-%d","Severity":"HIGH","Description":"%s"}]}`,
				i, i, strings.Repeat("d", 200))
		}
		output.WriteString(`]}`)

		result, err := parseResult(strings.NewReader(output.String()), []string{"npm"}, []string{"HIGH"}, 10000)

		require.NoError(t, err)
		assert.Equal(t, 20000, result.Summary["high"])
		assert.Len(t, result.Findings, 10000)
		assert.True(t, result.Truncated)
	})
}

func TestParseResult_InvalidOutput(t *testing.T) {
	for name, output := range map[string]string{
		"not JSON":            `Trivy crashed`,
		"empty":               ``,
		"cut off":             `{"SchemaVersion":2,"Results":[{"Target":"t","Type":"npm"`,
		"old schema":          `{"SchemaVersion":1,"Results":[]}`,
		"no schema":           `{"Results":[]}`,
		"results not a list":  `{"SchemaVersion":2,"Results":{}}`,
		"bad vulnerabilities": `{"SchemaVersion":2,"Results":[{"Type":"npm","Vulnerabilities":"x"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseResult(strings.NewReader(output), []string{"npm"}, []string{"HIGH"}, 10)
			assertClass(t, err, FailureOutputInvalid)
		})
	}
}

func TestValidateOptions(t *testing.T) {
	assert.NoError(t, ValidateOptions([]string{"npm", "node-pkg", "python_pkg", "debian12"}, []string{"HIGH", "CRITICAL"}))
	assert.NoError(t, ValidateOptions([]string{"npm"}, nil), "no severities: the caller uses the default")

	tooMany := make([]string, MaxPlatforms+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("p%d", i)
	}
	for name, invalid := range map[string]struct{ platforms, severities []string }{
		"no platforms":         {nil, []string{"HIGH"}},
		"too many platforms":   {tooMany, nil},
		"uppercase platform":   {[]string{"NPM"}, nil},
		"platform with a dot":  {[]string{"node.js"}, nil},
		"platform with spaces": {[]string{"n pm"}, nil},
		"empty platform":       {[]string{""}, nil},
		"lowercase severity":   {[]string{"npm"}, []string{"high"}},
		"unknown severity":     {[]string{"npm"}, []string{"SEVERE"}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, ValidateOptions(invalid.platforms, invalid.severities), ErrInvalidOptions)
		})
	}
}
