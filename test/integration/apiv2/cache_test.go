//go:build integration

package apiv2

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

var smallFindings = []runner.Finding{
	{ID: "CVE-1", Package: "lodash", Severity: "HIGH", Type: "npm"},
	{ID: "CVE-2", Package: "log4j", Severity: "CRITICAL", Type: "jar"},
	{ID: "CVE-3", Package: "minimist", Severity: "LOW", Type: "npm"},
}

func vulnerabilityIDs(response map[string]any) []string {
	var ids []string
	for _, v := range response["vulnerabilities"].([]any) {
		ids = append(ids, v.(map[string]any)["id"].(string))
	}
	return ids
}

func TestCache(t *testing.T) {
	t.Run("a hit renews confirmed_at, overwrites the request fields and creates no document", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm","jar"`, "")).Code)
		done := e.finish(t, smallFindings)
		time.Sleep(10 * time.Millisecond)

		w := e.post(`{"image":{"repository":"project","name":"app","tag":"v1"},"customer_ids":["cust-2"],"platforms":["npm"],` +
			`"severity":["HIGH"],"request_id":"req-2","customer_data":{"env":"prod"}}`)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		response := decode(t, w)
		assert.Equal(t, true, response["cached"])
		assert.Equal(t, true, response["db_unchanged"])
		assert.Equal(t, "done", response["state"])
		assert.Equal(t, []string{"CVE-1"}, vulnerabilityIDs(response), "filtered to npm and HIGH")
		assert.Equal(t, map[string]any{"critical": 0.0, "high": 1.0, "medium": 0.0, "low": 1.0, "unknown": 0.0}, response["summary"],
			"counts of npm only, at every severity")
		assert.Equal(t, []any{"npm"}, response["platforms_found"])
		assert.Equal(t, true, response["has_more_platforms"])
		assert.Equal(t, "ok", response["db"].(map[string]any)["freshness"])

		assert.EqualValues(t, 1, e.count(t))
		renewed := e.scan(t, done.ID)
		assert.True(t, renewed.ConfirmedAt.After(*done.ConfirmedAt), "confirmed_at renewed")
		assert.Equal(t, []string{"cust-2"}, renewed.CustomerIDs)
		assert.Equal(t, map[string]any{"env": "prod"}, renewed.CustomerData)
		assert.Equal(t, "req-2", renewed.LastRequestID)
		assert.Equal(t, done.Result, renewed.Result, "the result is not touched")
		raw := rawScan(t, e, done.ID)
		assert.NotContains(t, raw, "cached")
		assert.NotContains(t, raw, "db_unchanged")
	})

	t.Run("a hit on a tag whose last attempt failed serves the last good result and marks it done", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		done := e.finish(t, smallFindings[:1])
		setFields(t, e, done.ID, bson.M{"$set": bson.M{"state": "failed", "error": "exit status 1", "failure_class": "trivy_exit_error"}})

		w := e.post(body("v1", `"npm"`, ""))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		stored := e.scan(t, done.ID)
		assert.Equal(t, store.ScanDone, stored.State)
		assert.Empty(t, stored.Error)
		assert.Empty(t, stored.FailureClass)
	})

	t.Run("misses: force, a broader severity, a newer installed DB", func(t *testing.T) {
		for name, tc := range map[string]struct {
			request string
			before  func(e *env)
		}{
			"force":            {request: body("v1", `"npm"`, `"force":true`)},
			"broader severity": {request: body("v1", `"npm"`, `"severity":["LOW"]`)},
			"another platform": {request: body("v1", `"pip"`, "")},
			"newer installed DB": {request: body("v1", `"npm"`, ""), before: func(e *env) {
				state, _ := e.dbState.Get(context.Background(), "db")
				state.Metadata.UpdatedAt = state.Metadata.UpdatedAt.Add(time.Hour)
				require.NoError(t, e.dbState.Save(context.Background(), "db", state))
			}},
		} {
			t.Run(name, func(t *testing.T) {
				e := newEnv(t, nil)
				require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
				e.finish(t, smallFindings[:1])
				if tc.before != nil {
					tc.before(e)
				}

				w := e.post(tc.request)

				require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
				assert.Equal(t, "queued", e.scan(t, scanID("v1")).State)
			})
		}
	})

	t.Run("a broader severity rescans the union of the scopes", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		e.finish(t, smallFindings[:1])

		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"jar"`, `"severity":["LOW"]`)).Code)

		options := e.scan(t, scanID("v1")).Options
		assert.Equal(t, []string{"jar", "npm"}, options.Platforms)
		assert.Equal(t, []string{"CRITICAL", "HIGH", "LOW"}, options.Severity)
	})

	t.Run("a new tag with an already-scanned digest copies the result (GridFS too); copies are independent", func(t *testing.T) {
		e := newEnv(t, nil)
		e.registry.set("v1", "sha256:same")
		e.registry.set("v2", "sha256:same")
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		first := e.finish(t, manyFindings("npm", "OLD"))
		firstFiles := e.reportFiles(t, first.ID)
		require.Len(t, firstFiles, 1, "a large report is in GridFS")

		w := e.post(body("v2", `"npm"`, `"request_id":"req-v2"`))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		response := decode(t, w)
		assert.Equal(t, true, response["cached"])
		assert.Equal(t, scanID("v2"), response["scan_id"])
		assert.Len(t, vulnerabilityIDs(response), 30)
		copied := e.scan(t, scanID("v2"))
		assert.Equal(t, store.ScanDone, copied.State)
		assert.Equal(t, "v2", copied.Image.Tag)
		assert.Equal(t, "req-v2", copied.LastRequestID)
		require.NotNil(t, copied.ConfirmedAt)
		copiedFiles := e.reportFiles(t, copied.ID)
		require.Len(t, copiedFiles, 1, "the copy has its own file")
		assert.NotEqual(t, firstFiles[0], copiedFiles[0])
		assert.Equal(t, first.Result.Digest, copied.Result.Digest)
		assert.Equal(t, first.Result.SummaryByPlatform, copied.Result.SummaryByPlatform)
		assert.EqualValues(t, 2, e.count(t))

		// A rescan of v1 replaces its result and file; the copy keeps its own.
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, `"force":true`)).Code)
		e.finish(t, manyFindings("npm", "NEW"))
		assert.NotEqual(t, firstFiles, e.reportFiles(t, first.ID))
		report, err := e.reports.Load(context.Background(), e.scan(t, copied.ID))
		require.NoError(t, err)
		assert.Contains(t, report["findings"].(bson.A)[0].(bson.D), bson.E{Key: "id", Value: "OLD-0"})
	})

	t.Run("a copy may come from a tag that is being rescanned", func(t *testing.T) {
		e := newEnv(t, nil)
		e.registry.set("v1", "sha256:same")
		e.registry.set("v2", "sha256:same")
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		e.finish(t, smallFindings[:1])
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, `"force":true`)).Code)

		w := e.post(body("v2", `"npm"`, ""))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, true, decode(t, w)["cached"])
		assert.Equal(t, "queued", e.scan(t, scanID("v1")).State, "the source is not touched")
	})

	t.Run("a source whose report vanished is a miss after a second lookup", func(t *testing.T) {
		e := newEnv(t, nil)
		e.registry.set("v1", "sha256:same")
		e.registry.set("v2", "sha256:same")
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		first := e.finish(t, manyFindings("npm", "OLD"))
		ctx, cancel := e.client.OperationContext(context.Background())
		defer cancel()
		bucket := e.client.Database().GridFSBucket(options.GridFSBucket().SetName(store.ReportBucket))
		require.NoError(t, bucket.Delete(ctx, *first.Result.ReportGridFSID))

		w := e.post(body("v2", `"npm"`, ""))

		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		assert.Equal(t, "queued", e.scan(t, scanID("v2")).State)
	})
}

func rawScan(t *testing.T, e *env, id string) bson.M {
	ctx, cancel := e.client.OperationContext(context.Background())
	defer cancel()
	var doc bson.M
	require.NoError(t, e.client.Database().Collection(store.CollectionScans).FindOne(ctx, bson.M{"_id": id}).Decode(&doc))
	return doc
}

func setFields(t *testing.T, e *env, id string, update bson.M) {
	ctx, cancel := e.client.OperationContext(context.Background())
	defer cancel()
	_, err := e.client.Database().Collection(store.CollectionScans).UpdateOne(ctx, bson.M{"_id": id}, update, options.UpdateOne())
	require.NoError(t, err)
}
