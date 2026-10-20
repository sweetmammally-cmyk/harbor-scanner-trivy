package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
)

// TestServer_ShutdownDoesNotExit: Shutdown makes ListenAndServe return
// http.ErrServerClosed, which is the normal end and must not exit the process
// (it used to call os.Exit(1), which killed the test binary and, in the
// service, skipped the graceful shutdown of the workers).
func TestServer_ShutdownDoesNotExit(t *testing.T) {
	server, err := NewServer(etc.API{Addr: "127.0.0.1:0"}, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	server.ListenAndServe()
	time.Sleep(100 * time.Millisecond)

	server.Shutdown()
	time.Sleep(200 * time.Millisecond) // the serve goroutine has returned by now

	// Reaching this line means the process is still alive.
}
