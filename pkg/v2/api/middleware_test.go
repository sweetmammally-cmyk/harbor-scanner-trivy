package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

const testToken = "0123456789abcdef0123456789abcdef"

// lockedBuffer is a log buffer shared by the handler goroutines and the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *lockedBuffer {
	logs := &lockedBuffer{}
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(defaultLogger) })
	return logs
}

// echoHandler is a handler with one test route, /api/v2/echo/{id}, that
// decodes a JSON body on POST.
func echoHandler(t *testing.T, cfg config.Config, block chan struct{}) *Handler {
	cfg.AuthToken = testToken
	if cfg.MaxInflight == 0 {
		cfg.MaxInflight = 32
	}
	h := NewHandler(cfg)
	h.router.HandleFunc("/api/v2/echo/{id}", func(w http.ResponseWriter, r *http.Request) {
		if block != nil {
			<-block
		}
		var body struct {
			Name string `json:"name"`
		}
		if r.Method == http.MethodPost && !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, body)
	})
	return h
}

func request(method, path, token, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	var body errorBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
	return body.Error.Code
}

func TestAuthenticate(t *testing.T) {
	logs := captureLogs(t)
	h := echoHandler(t, config.Config{}, nil)

	for name, header := range map[string]string{
		"missing":      "",
		"wrong token":  "Bearer " + strings.Repeat("x", 32),
		"wrong scheme": "Basic " + testToken,
		"no scheme":    testToken,
		"prefix only":  "Bearer " + testToken[:31],
	} {
		r := request(http.MethodGet, "/api/v2/echo/1", "", "")
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		w := serve(h, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code, name)
		assert.Equal(t, CodeUnauthorized, errorCode(t, w), name)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Bearer", name)
	}

	w := serve(h, request(http.MethodGet, "/api/v2/echo/1", testToken, ""))
	assert.Equal(t, http.StatusOK, w.Code)
	lower := request(http.MethodGet, "/api/v2/echo/1", "", "")
	lower.Header.Set("Authorization", "bearer "+testToken)
	assert.Equal(t, http.StatusOK, serve(h, lower).Code, "the scheme is case-insensitive")

	w = serve(h, request(http.MethodGet, "/api/v2/unknown", "", ""))
	assert.Equal(t, http.StatusUnauthorized, w.Code, "unknown routes need the token too")

	assert.NotContains(t, logs.String(), testToken[:16], "tokens are never logged")
}

func TestLogRequests(t *testing.T) {
	logs := captureLogs(t)
	h := echoHandler(t, config.Config{}, nil)

	r := request(http.MethodPost, "/api/v2/echo/42", testToken, `{"name":"secret-body-value"}`)
	r.Header.Set("X-Request-ID", "req-abc:1")
	w := serve(h, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "req-abc:1", w.Header().Get("X-Request-ID"))
	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(logs.String())), &line), logs.String())
	assert.Equal(t, "request", line["msg"])
	assert.Equal(t, "POST", line["method"])
	assert.Equal(t, "/api/v2/echo/{id}", line["route"], "the route template, not the path")
	assert.EqualValues(t, 200, line["status"])
	assert.Equal(t, "req-abc:1", line["request_id"])
	assert.Contains(t, line, "duration_ms")
	assert.NotContains(t, logs.String(), "secret-body-value", "bodies are never logged")

	t.Run("an invalid or missing X-Request-ID is replaced", func(t *testing.T) {
		for _, id := range []string{"", "has space", strings.Repeat("a", 129)} {
			r := request(http.MethodGet, "/api/v2/echo/1", testToken, "")
			r.Header.Set("X-Request-ID", id)
			got := serve(h, r).Header().Get("X-Request-ID")
			assert.Regexp(t, "^[0-9a-f]{32}$", got)
		}
	})

	t.Run("401 and 404 are logged too", func(t *testing.T) {
		serve(h, request(http.MethodGet, "/api/v2/nothing", "", ""))
		assert.Contains(t, logs.String(), `"route":"unmatched","status":401`)
	})
}

func TestLimitInflight(t *testing.T) {
	block := make(chan struct{})
	h := echoHandler(t, config.Config{MaxInflight: 2}, block)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serve(h, request(http.MethodPost, "/api/v2/echo/1", testToken, `{}`))
		}()
	}
	require.Eventually(t, func() bool { return len(h.inflight) == 2 }, time.Second, time.Millisecond)

	w := serve(h, request(http.MethodPost, "/api/v2/echo/1", testToken, `{}`))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, CodeQueueFull, errorCode(t, w))
	assert.Equal(t, "1", w.Header().Get("Retry-After"))

	close(block)
	wg.Wait()
	assert.Equal(t, http.StatusOK, serve(h, request(http.MethodPost, "/api/v2/echo/1", testToken, `{}`)).Code)
	assert.Equal(t, http.StatusOK, serve(h, request(http.MethodGet, "/api/v2/echo/1", testToken, "")).Code, "GETs are not limited")
}

func TestDecodeJSON(t *testing.T) {
	h := echoHandler(t, config.Config{}, nil)

	w := serve(h, request(http.MethodPost, "/api/v2/echo/1", testToken, `{"name":"a"}`))
	assert.Equal(t, http.StatusOK, w.Code)

	charset := request(http.MethodPost, "/api/v2/echo/1", testToken, `{"name":"a"}`)
	charset.Header.Set("Content-Type", "application/json; charset=utf-8")
	assert.Equal(t, http.StatusOK, serve(h, charset).Code)

	for name, tc := range map[string]struct {
		body        string
		contentType string
		status      int
	}{
		"unknown field":      {body: `{"name":"a","extra":1}`, status: http.StatusBadRequest},
		"trailing data":      {body: `{"name":"a"} {"name":"b"}`, status: http.StatusBadRequest},
		"not JSON":           {body: `name=a`, status: http.StatusBadRequest},
		"wrong type":         {body: `{"name":1}`, status: http.StatusBadRequest},
		"oversized":          {body: `{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}`, status: http.StatusRequestEntityTooLarge},
		"wrong content type": {body: `{"name":"a"}`, contentType: "text/plain", status: http.StatusUnsupportedMediaType},
	} {
		r := request(http.MethodPost, "/api/v2/echo/1", testToken, tc.body)
		if tc.contentType != "" {
			r.Header.Set("Content-Type", tc.contentType)
		}
		w := serve(h, r)
		assert.Equal(t, tc.status, w.Code, name)
		assert.Equal(t, CodeInvalidRequest, errorCode(t, w), name)
	}
}
