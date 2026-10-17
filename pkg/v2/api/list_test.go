package api

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

func TestParseListQuery(t *testing.T) {
	filter, err := parseListQuery(url.Values{})
	require.NoError(t, err)
	assert.Equal(t, store.ScanFilter{Limit: 50}, filter)

	cursor := base64.RawURLEncoding.EncodeToString([]byte(`{"t":"2026-10-17T10:00:00Z","id":"abc"}`))
	filter, err = parseListQuery(url.Values{
		"customer_id": {"c1"}, "digest": {"sha256:a"}, "repository": {"project"}, "name": {"app"}, "state": {"done"},
		"platform": {"npm"}, "request_id": {"req-1"}, "from": {"2026-10-01T00:00:00Z"}, "to": {"2026-10-31T00:00:00Z"},
		"limit": {"200"}, "cursor": {cursor},
	})
	require.NoError(t, err)
	assert.Equal(t, store.ScanFilter{
		CustomerID: "c1", Digest: "sha256:a", Repository: "project", Name: "app", State: "done", Platform: "npm", RequestID: "req-1",
		From: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC),
		AfterCreatedAt: time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC), AfterID: "abc", Limit: 200,
	}, filter)

	for name, query := range map[string]url.Values{
		"unknown parameter":  {"customer": {"c1"}},
		"bad state":          {"state": {"running"}},
		"limit 0":            {"limit": {"0"}},
		"limit 201":          {"limit": {"201"}},
		"limit not a number": {"limit": {"many"}},
		"bad from":           {"from": {"yesterday"}},
		"bad to":             {"to": {"2026-13-01"}},
		"bad cursor":         {"cursor": {"!!!"}},
		"cursor not JSON":    {"cursor": {base64.RawURLEncoding.EncodeToString([]byte("x"))}},
	} {
		_, err := parseListQuery(query)
		assert.Error(t, err, name)
	}
}
