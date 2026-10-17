//go:build integration

package apiv2

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/runner"
)

func TestGetScan(t *testing.T) {
	get := func(e *env, id, query string) (int, map[string]any, http.Header) {
		w := e.do(http.MethodGet, "/api/v2/scans/"+id+query, "")
		return w.Code, decode(t, w), w.Header()
	}

	t.Run("unknown scan: 404 not_found", func(t *testing.T) {
		e := newEnv(t, nil)
		code, response, _ := get(e, scanID("nope"), "")
		assert.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, map[string]any{"scan_id": scanID("nope"), "state": "not_found"}, response)
	})

	t.Run("queued: 200 with Retry-After and no findings", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)

		code, response, header := get(e, scanID("v1"), "")

		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "queued", response["state"])
		assert.Equal(t, "2", header.Get("Retry-After"))
		assert.NotContains(t, response, "vulnerabilities")
		assert.NotContains(t, response, "previous", "no result yet")
		assert.Equal(t, "sha256:v1", response["image"].(map[string]any)["digest"])
		assert.Contains(t, response, "db")
	})

	t.Run("done: the full stored scope by default, filtered with query parameters", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm","jar"`, "")).Code)
		e.finish(t, smallFindings)

		code, response, header := get(e, scanID("v1"), "")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "done", response["state"])
		assert.Empty(t, header.Get("Retry-After"))
		assert.ElementsMatch(t, []string{"CVE-1", "CVE-2"}, vulnerabilityIDs(response))
		assert.NotContains(t, response, "cached", "only POST hits carry cached")
		assert.Equal(t, []any{"jar", "npm"}, response["platforms_requested"])

		code, response, _ = get(e, scanID("v1"), "?platforms=JAR&severity=critical")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, []string{"CVE-2"}, vulnerabilityIDs(response))
		assert.Equal(t, 1.0, response["summary"].(map[string]any)["critical"])
		assert.Equal(t, 0.0, response["summary"].(map[string]any)["low"], "jar has no low findings; npm is not counted")

		code, response, _ = get(e, scanID("v1"), "?platforms=pip")
		assert.Equal(t, http.StatusBadRequest, code, "outside the stored scope")
		assert.Equal(t, "invalid_request", response["error"].(map[string]any)["code"])
	})

	t.Run("a failed rescan: class, a fixed message and the previous result", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)
		done := e.finish(t, smallFindings[:1])
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, `"force":true`)).Code)

		code, response, header := get(e, scanID("v1"), "")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "queued", response["state"])
		assert.Equal(t, "2", header.Get("Retry-After"))
		previous := response["previous"].(map[string]any)
		assert.Equal(t, done.Result.Digest, previous["digest"])
		assert.Equal(t, 1.0, previous["summary"].(map[string]any)["high"])
		assert.Contains(t, previous, "confirmed_at")

		claimed, err := e.queue.Claim(context.Background(), "w")
		require.NoError(t, err)
		require.NoError(t, e.queue.Fail(context.Background(), claimed, runner.FailureExit,
			"exit status 1: stderr: FATAL open /home/scanner/.cache/x: permission denied"))

		code, response, header = get(e, scanID("v1"), "")
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "failed", response["state"])
		assert.Empty(t, header.Get("Retry-After"))
		assert.Equal(t, map[string]any{"class": "trivy_exit_error", "message": "Trivy could not scan the image"}, response["error"])
		assert.NotContains(t, e.do(http.MethodGet, "/api/v2/scans/"+scanID("v1"), "").Body.String(), "/home/scanner",
			"no stored detail, paths or stderr")
		assert.Contains(t, response, "previous")
		assert.NotContains(t, response, "vulnerabilities")
	})
}
