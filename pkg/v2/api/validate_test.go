package api

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

var now = time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)

func validRequest() scanRequest {
	return scanRequest{
		Image:       imageRequest{Repository: "customer-123", Name: "app", Tag: "v1.2.0"},
		CustomerIDs: []string{"cust-123"},
		Platforms:   []string{"npm"},
	}
}

func TestValidate(t *testing.T) {
	t.Run("defaults and normalization", func(t *testing.T) {
		request := validRequest()
		request.RequestID = "temporal:wf-1.run_2"
		request.RequestedAt = "2026-10-17T09:59:00Z"
		request.Platforms = []string{"NPM", "jar", "npm", "Debian"}
		request.CustomerData = map[string]any{"env": "prod"}

		scan, err := validate(request, now, 6*time.Hour)

		require.NoError(t, err)
		assert.Equal(t, store.Scan{
			LastRequestID: "temporal:wf-1.run_2",
			RequestedAt:   time.Date(2026, 10, 17, 9, 59, 0, 0, time.UTC),
			ReceivedAt:    now,
			CustomerIDs:   []string{"cust-123"},
			CustomerData:  map[string]any{"env": "prod"},
			Image:         store.Image{Repository: "customer-123", Name: "app", Tag: "v1.2.0"},
			Options: store.ScanOptions{Platforms: []string{"debian", "jar", "npm"}, Severity: []string{"CRITICAL", "HIGH"},
				MaxDBAge: 6 * time.Hour},
		}, scan)
	})

	t.Run("severities are uppercased, deduplicated and sorted; max_db_age accepts days", func(t *testing.T) {
		request := validRequest()
		request.Severity = []string{"high", "LOW", "High"}
		request.MaxDBAge = "1d"

		scan, err := validate(request, now, 6*time.Hour)

		require.NoError(t, err)
		assert.Equal(t, []string{"HIGH", "LOW"}, scan.Options.Severity)
		assert.Equal(t, 24*time.Hour, scan.Options.MaxDBAge)
	})

	for name, change := range map[string]func(*scanRequest){
		"request_id with a space":     func(r *scanRequest) { r.RequestID = "a b" },
		"request_id too long":         func(r *scanRequest) { r.RequestID = strings.Repeat("a", 129) },
		"requested_at not RFC 3339":   func(r *scanRequest) { r.RequestedAt = "yesterday" },
		"requested_at in the future":  func(r *scanRequest) { r.RequestedAt = "2026-10-17T10:06:00Z" },
		"invalid repository":          func(r *scanRequest) { r.Image.Repository = "Customer" },
		"repository with ..":          func(r *scanRequest) { r.Image.Repository = "a/../b" },
		"invalid tag":                 func(r *scanRequest) { r.Image.Tag = "-v1" },
		"missing tag":                 func(r *scanRequest) { r.Image.Tag = "" },
		"no customer_ids":             func(r *scanRequest) { r.CustomerIDs = nil },
		"too many customer_ids":       func(r *scanRequest) { r.CustomerIDs = make([]string, 101) },
		"empty customer_id":           func(r *scanRequest) { r.CustomerIDs = []string{""} },
		"customer_id too long":        func(r *scanRequest) { r.CustomerIDs = []string{strings.Repeat("c", 129)} },
		"customer_data over 64 KiB":   func(r *scanRequest) { r.CustomerData = map[string]any{"x": strings.Repeat("d", 64<<10)} },
		"no platforms":                func(r *scanRequest) { r.Platforms = nil },
		"too many platforms":          func(r *scanRequest) { r.Platforms = strings.Split("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u", ",") },
		"invalid platform":            func(r *scanRequest) { r.Platforms = []string{"np m"} },
		"unknown severity":            func(r *scanRequest) { r.Severity = []string{"SEVERE"} },
		"max_db_age not a duration":   func(r *scanRequest) { r.MaxDBAge = "soon" },
		"max_db_age below one minute": func(r *scanRequest) { r.MaxDBAge = "30s" },
		"max_db_age above 30 days":    func(r *scanRequest) { r.MaxDBAge = "31d" },
	} {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			change(&request)
			_, err := validate(request, now, 6*time.Hour)
			assert.Error(t, err)
		})
	}

	t.Run("twenty platforms and 30 days are accepted", func(t *testing.T) {
		request := validRequest()
		request.Platforms = strings.Split("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t", ",")
		request.MaxDBAge = "30d"
		_, err := validate(request, now, 6*time.Hour)
		assert.NoError(t, err)
	})
}
