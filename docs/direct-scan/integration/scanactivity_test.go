package scanactivity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

// fakeScanner answers POST and GET with the next scripted reply of each.
type fakeScanner struct {
	mu    sync.Mutex
	posts []reply
	gets  []reply
	seen  []string
}

type reply struct {
	status     int
	retryAfter string
	body       string
}

func (f *fakeScanner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	queue := &f.gets
	if r.Method == http.MethodPost {
		queue = &f.posts
	}
	next := (*queue)[0]
	*queue = (*queue)[1:]
	if next.retryAfter != "" {
		w.Header().Set("Retry-After", next.retryAfter)
	}
	w.WriteHeader(next.status)
	_, _ = w.Write([]byte(next.body))
}

func run(t *testing.T, fake *fakeScanner) (ScanOutcome, []string, error) {
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	scanner := &Scanner{BaseURL: server.URL, Token: "test-token", HTTP: server.Client(), MaxWait: 10 * time.Millisecond}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestActivityEnvironment()
	env.RegisterActivity(scanner.ScanImage)
	value, err := env.ExecuteActivity(scanner.ScanImage, ScanInput{Repository: "project", Name: "app", Tag: "v1",
		CustomerIDs: []string{"c1"}, Platforms: []string{"npm"}})
	var result ScanOutcome
	if err == nil {
		if getErr := value.Get(&result); getErr != nil {
			t.Fatal(getErr)
		}
	}
	return result, fake.seen, err
}

const (
	queued = `{"scan_id":"abc","state":"queued"}`
	done   = `{"scan_id":"abc","state":"done","db":{"freshness":"ok"},"vulnerabilities":[]}`
)

func TestScanImage(t *testing.T) {
	t.Run("409, then 202, poll while queued, then done", func(t *testing.T) {
		result, seen, err := run(t, &fakeScanner{
			posts: []reply{{status: 409, retryAfter: "5", body: `{"error":{"code":"scan_in_progress"}}`}, {status: 202, body: queued}},
			gets:  []reply{{status: 200, retryAfter: "2", body: queued}, {status: 200, body: done}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.ScanID != "abc" || result.Stale || result.Cached {
			t.Fatalf("unexpected outcome %+v", result)
		}
		if strings.Join(seen, ",") != "POST /api/v2/scans,POST /api/v2/scans,GET /api/v2/scans/abc,GET /api/v2/scans/abc" {
			t.Fatalf("unexpected calls %v", seen)
		}
	})

	t.Run("a cache hit answers at once", func(t *testing.T) {
		result, _, err := run(t, &fakeScanner{posts: []reply{{status: 200,
			body: `{"scan_id":"abc","state":"done","cached":true,"db":{"freshness":"stale"}}`}}})
		if err != nil {
			t.Fatal(err)
		}
		if !result.Cached || !result.Stale {
			t.Fatalf("unexpected outcome %+v", result)
		}
	})

	t.Run("image_not_found is not retried", func(t *testing.T) {
		_, _, err := run(t, &fakeScanner{posts: []reply{{status: 404, body: `{"error":{"code":"image_not_found"}}`}}})
		var appErr *temporal.ApplicationError
		if !errors.As(err, &appErr) || !appErr.NonRetryable() || appErr.Type() != "image_not_found" {
			t.Fatalf("want a non-retryable image_not_found, got %v", err)
		}
	})

	t.Run("failed with a previous result is a stale result", func(t *testing.T) {
		result, _, err := run(t, &fakeScanner{
			posts: []reply{{status: 202, body: queued}},
			gets: []reply{{status: 200, body: `{"scan_id":"abc","state":"failed","error":{"class":"trivy_timeout","message":"the scan timed out"},` +
				`"previous":{"digest":"sha256:1","summary":{"high":1}}}`}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.Stale || result.FailureClass != "trivy_timeout" {
			t.Fatalf("unexpected outcome %+v", result)
		}
	})

	t.Run("failed without a previous result is a retryable error named by its class", func(t *testing.T) {
		_, _, err := run(t, &fakeScanner{
			posts: []reply{{status: 202, body: queued}},
			gets:  []reply{{status: 200, body: `{"scan_id":"abc","state":"failed","error":{"class":"platform_not_found"}}`}},
		})
		var appErr *temporal.ApplicationError
		if !errors.As(err, &appErr) || appErr.NonRetryable() || appErr.Type() != "platform_not_found" {
			t.Fatalf("want a retryable platform_not_found, got %v", err)
		}
	})
}
