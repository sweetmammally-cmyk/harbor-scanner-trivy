//go:build integration

package apiv2

import (
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

func TestPostScan(t *testing.T) {
	t.Run("a new tag is queued: 202 with scan_id, state and db", func(t *testing.T) {
		e := newEnv(t, nil)

		w := e.post(body("v1", `"NPM"`, `"request_id":"req-1","requested_at":"2026-10-17T09:00:00Z"`))

		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		response := decode(t, w)
		assert.Equal(t, scanID("v1"), response["scan_id"])
		assert.Equal(t, "queued", response["state"])
		db := response["db"].(map[string]any)
		assert.Equal(t, "ok", db["freshness"], "no result yet: the local DB state")
		assert.Contains(t, db, "updated_at")
		assert.Contains(t, db, "last_upstream_check_at")
		stored := e.scan(t, scanID("v1"))
		assert.Equal(t, []string{"npm"}, stored.Options.Platforms)
		assert.Equal(t, []string{"CRITICAL", "HIGH"}, stored.Options.Severity)
		assert.Equal(t, "req-1", stored.LastRequestID)
		assert.Equal(t, "sha256:v1", stored.Image.Digest)
		assert.False(t, stored.ReceivedAt.IsZero())
		assert.Equal(t, 2026, stored.RequestedAt.Year())
	})

	t.Run("while the tag is queued: a covered request (even with force) gets 200 and changes nothing", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm","jar"`, "")).Code)
		before := e.scan(t, scanID("v1"))

		for _, extra := range []string{"", `"force":true`, `"severity":["critical"]`} {
			w := e.post(body("v1", `"jar"`, extra))
			require.Equal(t, http.StatusOK, w.Code, extra)
			assert.Equal(t, "queued", decode(t, w)["state"])
		}
		assert.Equal(t, before, e.scan(t, scanID("v1")))
		assert.EqualValues(t, 1, e.count(t))
	})

	t.Run("while the tag is queued: an uncovered request or a moved tag gets 409", func(t *testing.T) {
		e := newEnv(t, nil)
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)

		w := e.post(body("v1", `"pip"`, ""))
		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Equal(t, "scan_in_progress", errorCode(t, w))
		assert.Equal(t, "5", w.Header().Get("Retry-After"))

		w = e.post(body("v1", `"npm"`, `"severity":["LOW"]`))
		assert.Equal(t, http.StatusConflict, w.Code)

		e.registry.set("v1", "sha256:moved")
		w = e.post(body("v1", `"npm"`, ""))
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("queue full: 429 queue_full with Retry-After", func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Config) { cfg.QueueMaxLength = 1 })
		require.Equal(t, http.StatusAccepted, e.post(body("v1", `"npm"`, "")).Code)

		w := e.post(body("v2", `"npm"`, ""))

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "queue_full", errorCode(t, w))
		assert.Equal(t, "10", w.Header().Get("Retry-After"))
		assert.Equal(t, http.StatusOK, e.post(body("v1", `"npm"`, "")).Code, "a covered request still joins")
	})

	t.Run("ten concurrent POSTs for one tag on two replicas create one document and one scan", func(t *testing.T) {
		e := newEnv(t, nil)
		other := e.newReplica(t)
		var wg sync.WaitGroup
		codes := make([]int, 10)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				replica := e
				if i%2 == 1 {
					replica = other
				}
				codes[i] = replica.post(body("v1", `"npm"`, "")).Code
			}()
		}
		wg.Wait()

		accepted := 0
		for _, code := range codes {
			assert.Contains(t, []int{http.StatusAccepted, http.StatusOK}, code)
			if code == http.StatusAccepted {
				accepted++
			}
		}
		assert.Equal(t, 1, accepted)
		assert.EqualValues(t, 1, e.count(t))
	})
}
