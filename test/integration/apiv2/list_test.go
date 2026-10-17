//go:build integration

package apiv2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// list calls GET /api/v2/scans and returns the scan ids and the next cursor.
func (e *env) list(t *testing.T, query url.Values) ([]string, string) {
	w := e.do(http.MethodGet, "/api/v2/scans?"+query.Encode(), "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var response struct {
		Items []struct {
			ScanID string `json:"scan_id"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	ids := []string{}
	for _, item := range response.Items {
		ids = append(ids, item.ScanID)
	}
	return ids, response.NextCursor
}

func TestListScans(t *testing.T) {
	t.Run("filters", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, `"request_id":"req-1"`)).Code)
		e.finish(t, smallFindings[:1])
		require.Equal(t, http.StatusAccepted, e.post(`{"image":{"repository":"other","name":"svc","tag":"v2"},"customer_ids":["cust-2"],"platforms":["jar"]}`).Code)
		e.registry.set("v1", "sha256:moved")
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code, "v1 moved: queued again, its result stays")
		v2 := store.ScanID(store.Image{Repository: "other", Name: "svc", Tag: "v2"})

		for name, tc := range map[string]struct {
			query url.Values
			want  []string
		}{
			"all, newest first":            {url.Values{}, []string{v2, scanID("v1")}},
			"customer":                     {url.Values{"customer_id": {"cust-2"}}, []string{v2}},
			"digest of the result":         {url.Values{"digest": {"sha256:v1"}}, []string{scanID("v1")}},
			"digest of the latest request": {url.Values{"digest": {"sha256:moved"}}, []string{scanID("v1")}},
			"repository":                   {url.Values{"repository": {"other"}}, []string{v2}},
			"name":                         {url.Values{"name": {"app"}}, []string{scanID("v1")}},
			"state":                        {url.Values{"state": {"queued"}}, []string{v2, scanID("v1")}},
			"platform found in the image":  {url.Values{"platform": {"debian"}}, []string{scanID("v1")}},
			"request id":                   {url.Values{"request_id": {"req-1"}}, []string{}},
			"from in the future":           {url.Values{"from": {time.Now().Add(time.Hour).Format(time.RFC3339)}}, []string{}},
			"to in the past":               {url.Values{"to": {"2020-01-01T00:00:00Z"}}, []string{}},
		} {
			ids, _ := e.list(t, tc.query)
			assert.Equal(t, tc.want, ids, name)
		}
		ids, _ := e.list(t, url.Values{"request_id": {""}})
		assert.Len(t, ids, 2, "an empty filter does not filter")
	})

	t.Run("items have no findings or report", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		e.finish(t, smallFindings[:1])

		w := e.do(http.MethodGet, "/api/v2/scans", "")

		require.Equal(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), "vulnerabilities")
		assert.NotContains(t, w.Body.String(), "findings")
		assert.NotContains(t, w.Body.String(), "CVE-1")
		assert.Contains(t, w.Body.String(), `"summary"`)
	})

	t.Run("pagination is stable while new tags are inserted", func(t *testing.T) {
		e := newEnv(t, nil)
		var want []string
		for i := 0; i < 7; i++ {
			tag := fmt.Sprintf("v%d", i)
			require.Equal(t, http.StatusAccepted, e.post(body(tag, `"npm"`, "")).Code)
			want = append([]string{scanID(tag)}, want...)
			time.Sleep(2 * time.Millisecond)
		}

		var got []string
		cursor := ""
		for page := 0; page < 10; page++ {
			query := url.Values{"limit": {"3"}}
			if cursor != "" {
				query.Set("cursor", cursor)
			}
			ids, next := e.list(t, query)
			got = append(got, ids...)
			require.Equal(t, http.StatusAccepted, e.post(body(fmt.Sprintf("new%d", page), `"npm"`, "")).Code)
			if next == "" {
				break
			}
			cursor = next
		}

		assert.Equal(t, want, got, "every original tag once, in order; tags inserted meanwhile are not in later pages")
	})

	t.Run("customer_id and digest queries use indexes", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)

		for name, filter := range map[string]store.ScanFilter{
			"customer_id": {CustomerID: "cust-1", Limit: 51},
			"digest":      {Digest: "sha256:v1", Limit: 51},
			"cursor":      {CustomerID: "cust-1", AfterCreatedAt: time.Now(), AfterID: "x", Limit: 51},
		} {
			ctx, cancel := e.client.OperationContext(context.Background())
			var plan struct {
				QueryPlanner struct {
					WinningPlan bson.Raw `bson:"winningPlan"`
				} `bson:"queryPlanner"`
			}
			err := e.client.Database().RunCommand(ctx, bson.D{
				{Key: "explain", Value: bson.D{
					{Key: "find", Value: store.CollectionScans},
					{Key: "filter", Value: store.ListQuery(filter)},
					{Key: "sort", Value: store.ListSort},
					{Key: "limit", Value: filter.Limit},
				}},
				{Key: "verbosity", Value: "queryPlanner"},
			}).Decode(&plan)
			cancel()
			require.NoError(t, err, name)
			winning := plan.QueryPlanner.WinningPlan.String()
			assert.NotContains(t, winning, "COLLSCAN", name)
			assert.Contains(t, winning, "IXSCAN", name)
		}
	})
}
