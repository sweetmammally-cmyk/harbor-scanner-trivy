package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// lockedBuffer is a log buffer that the Monitor goroutine and the test can share.
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
	t.Helper()
	logs := &lockedBuffer{}
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(defaultLogger) })
	return logs
}

func testConfig(uri string) config.Config {
	return config.Config{
		MongoURI:                    uri,
		MongoDB:                     "scanner_test",
		MongoConnectTimeout:         200 * time.Millisecond,
		MongoServerSelectionTimeout: 200 * time.Millisecond,
		MongoOperationTimeout:       time.Second,
	}
}

func TestNewClient_UnreachableIsNotAnError(t *testing.T) {
	start := time.Now()
	client, err := NewClient(testConfig("mongodb://127.0.0.1:1/?directConnection=true"))

	require.NoError(t, err, "the driver connects in the background")
	assert.Less(t, time.Since(start), time.Second, "no network I/O in NewClient")
	assert.False(t, client.Up(), "not up before the first ping")
	assert.Equal(t, "scanner_test", client.Database().Name())
}

func TestClient_CheckOnce(t *testing.T) {
	client, err := NewClient(testConfig("mongodb://127.0.0.1:1/?directConnection=true"))
	require.NoError(t, err)
	var pingErr error
	client.ping = func(ctx context.Context) error {
		_, hasDeadline := ctx.Deadline()
		assert.True(t, hasDeadline, "every Mongo call has a deadline")
		return pingErr
	}
	client.ensureSchema = func(ctx context.Context) error { return nil }
	logs := captureLogs(t)

	pingErr = errors.New("connection refused")
	client.checkOnce(context.Background())
	assert.False(t, client.Up())
	assert.Equal(t, 1, strings.Count(logs.String(), "MongoDB is unreachable"), "the first failure is logged")

	client.checkOnce(context.Background())
	assert.Equal(t, 1, strings.Count(logs.String(), "MongoDB is unreachable"), "no repeated log while down")

	pingErr = nil
	client.checkOnce(context.Background())
	assert.True(t, client.Up())
	assert.Contains(t, logs.String(), `"msg":"MongoDB is reachable"`)

	pingErr = errors.New("connection reset")
	client.checkOnce(context.Background())
	assert.False(t, client.Up())
	assert.Equal(t, 2, strings.Count(logs.String(), "MongoDB is unreachable"), "going down is logged")
}

func TestClient_Monitor(t *testing.T) {
	client, err := NewClient(testConfig("mongodb://127.0.0.1:1/?directConnection=true"))
	require.NoError(t, err)
	var pings atomic.Int32
	client.ping = func(ctx context.Context) error {
		pings.Add(1)
		return nil
	}
	client.ensureSchema = func(ctx context.Context) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		client.Monitor(ctx, 10*time.Millisecond)
		close(stopped)
	}()

	require.Eventually(t, func() bool { return pings.Load() >= 3 }, 5*time.Second, 5*time.Millisecond)
	assert.True(t, client.Up())

	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Monitor did not stop")
	}
}

func TestClient_OperationContext(t *testing.T) {
	client, err := NewClient(testConfig("mongodb://127.0.0.1:1/?directConnection=true"))
	require.NoError(t, err)

	ctx, cancel := client.OperationContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(time.Second), deadline, 100*time.Millisecond)
}

func TestRedaction(t *testing.T) {
	secrets := []string{"s3cret", "p@ss", "p%40ss", "mongouser"}

	t.Run("driver errors for malformed URIs never contain the URI or the password", func(t *testing.T) {
		for _, uri := range []string{
			"mongodb://mongouser:s3cret@host:notaport/db",
			"mongodb://mongouser:s3cret@/db",
			"mongodb://mongouser:p%40ss@host/db?connectTimeoutMS=abc",
			"mongodb+srv://mongouser:s3cret@host:27017/db",
			"mongodb://mongouser:s3cret@host/db?authMechanism=NOPE",
			"http://mongouser:s3cret@host/db",
		} {
			_, err := NewClient(testConfig(uri))
			require.Error(t, err, uri)
			for _, secret := range secrets {
				assert.NotContains(t, err.Error(), secret, "%s -> %s", uri, err.Error())
			}
		}
	})

	t.Run("an error that quotes the URI is cleaned", func(t *testing.T) {
		uri := "mongodb://mongouser:p%40ss@db1:27017,db2:27017/scanner?w=majority"
		err := errors.New(`error parsing uri "` + uri + `": user mongouser:p%40ss, password p@ss`)

		redacted := redactURI(err, uri)

		for _, secret := range secrets {
			assert.NotContains(t, redacted.Error(), secret)
		}
		assert.Equal(t, `error parsing uri "xxxxx": user xxxxx, password xxxxx`, redacted.Error())
	})

	t.Run("URI without credentials is still removed", func(t *testing.T) {
		uri := "mongodb://db1:27017/scanner"
		assert.Equal(t, "bad uri xxxxx", redactURI(errors.New("bad uri "+uri), uri).Error())
	})

	t.Run("schema errors do not log the URI", func(t *testing.T) {
		uri := "mongodb://mongouser:s3cret@127.0.0.1:1/scanner?directConnection=true"
		client, err := NewClient(testConfig(uri))
		require.NoError(t, err)
		client.ping = func(ctx context.Context) error { return nil }
		client.ensureSchema = func(ctx context.Context) error { return errors.New("failed on " + uri) }
		logs := captureLogs(t)

		client.checkOnce(context.Background())

		require.Contains(t, logs.String(), "MongoDB schema is not ready")
		for _, secret := range secrets {
			assert.NotContains(t, logs.String(), secret)
		}
	})

	t.Run("ping failures against a server with credentials do not log them", func(t *testing.T) {
		client, err := NewClient(testConfig("mongodb://mongouser:s3cret@127.0.0.1:1/scanner?directConnection=true"))
		require.NoError(t, err)
		logs := captureLogs(t)

		client.checkOnce(context.Background())

		require.Contains(t, logs.String(), "MongoDB is unreachable")
		for _, secret := range secrets {
			assert.NotContains(t, logs.String(), secret)
		}
	})
}

func TestClient_SchemaReadiness(t *testing.T) {
	client, err := NewClient(testConfig("mongodb://127.0.0.1:1/?directConnection=true"))
	require.NoError(t, err)
	var pingErr, schemaErr error
	ensureCalls := 0
	client.ping = func(ctx context.Context) error { return pingErr }
	client.ensureSchema = func(ctx context.Context) error {
		ensureCalls++
		return schemaErr
	}
	logs := captureLogs(t)

	// Up, but the schema step fails: not ready, retried on the next check, logged once.
	schemaErr = errors.New("index scans.state_queued_at conflicts with an existing index")
	client.checkOnce(context.Background())
	client.checkOnce(context.Background())
	assert.True(t, client.Up())
	assert.False(t, client.Ready(), "readiness needs the schema too")
	assert.Equal(t, 2, ensureCalls, "retried until it succeeds")
	assert.Equal(t, 1, strings.Count(logs.String(), "MongoDB schema is not ready"))
	assert.Contains(t, logs.String(), "scans.state_queued_at")

	// The schema step succeeds: ready, and not run again while Mongo stays up.
	schemaErr = nil
	client.checkOnce(context.Background())
	client.checkOnce(context.Background())
	assert.True(t, client.Ready())
	assert.Equal(t, 3, ensureCalls)
	assert.Contains(t, logs.String(), fmt.Sprintf(`"msg":"MongoDB schema is ready","schema_version":%d`, SchemaVersion))

	// Mongo goes down: not ready, and the schema step runs again when it comes back.
	pingErr = errors.New("connection refused")
	client.checkOnce(context.Background())
	assert.False(t, client.Ready())
	pingErr = nil
	client.checkOnce(context.Background())
	assert.True(t, client.Ready())
	assert.Equal(t, 4, ensureCalls, "ensure schema on every up transition")
}
