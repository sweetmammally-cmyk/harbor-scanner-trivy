package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetScan_BeforeTheStore(t *testing.T) {
	h := newTestHandler(&fakeResolver{}, readiness{})

	for _, id := range []string{"abc", strings.Repeat("A", 64), strings.Repeat("a", 63) + "g", strings.Repeat("a", 65)} {
		w := serve(h, request(http.MethodGet, "/api/v2/scans/"+id, testToken, ""))
		assert.Equal(t, http.StatusNotFound, w.Code, id)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, map[string]any{"state": "not_found"}, body, "an invalid id is not echoed")
	}

	valid := "/api/v2/scans/" + strings.Repeat("a", 64)
	w := serve(h, request(http.MethodGet, valid+"?severity=SEVERE", testToken, ""))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, CodeInvalidRequest, errorCode(t, w))

	w = serve(h, request(http.MethodGet, valid, testToken, ""))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, CodeStoreUnavailable, errorCode(t, w))

	assert.Equal(t, http.StatusUnauthorized, serve(h, request(http.MethodGet, valid, "", "")).Code)
}
