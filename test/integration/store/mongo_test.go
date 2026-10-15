//go:build integration

package store

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// startMongo starts a mongo:7 container and returns its host:port.
func startMongo(t *testing.T) string {
	ctx := context.Background()
	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "mongo:7",
			ExposedPorts: []string{"27017/tcp"},
			WaitingFor:   wait.ForListeningPort("27017/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err, "should start mongo container")
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "27017")
	require.NoError(t, err)
	return net.JoinHostPort(host, port.Port())
}

// forwarder forwards a fixed local address to Mongo and can be switched off and
// on, to make Mongo unreachable and reachable again without moving its port.
type forwarder struct {
	addr   string
	target string

	mu       sync.Mutex
	listener net.Listener
	conns    []net.Conn
}

// newForwarder reserves a free local address; it starts switched off.
func newForwarder(t *testing.T, target string) *forwarder {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	f := &forwarder{addr: addr, target: target}
	t.Cleanup(f.stop)
	return f
}

func (f *forwarder) start(t *testing.T) {
	listener, err := net.Listen("tcp", f.addr)
	require.NoError(t, err)
	f.mu.Lock()
	f.listener = listener
	f.mu.Unlock()
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("tcp", f.target)
			if err != nil {
				_ = client.Close()
				continue
			}
			f.mu.Lock()
			f.conns = append(f.conns, client, upstream)
			f.mu.Unlock()
			go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
			go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
		}
	}()
}

// stop closes the listener and every open connection, like Mongo going away.
func (f *forwarder) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		_ = f.listener.Close()
		f.listener = nil
	}
	for _, conn := range f.conns {
		_ = conn.Close()
	}
	f.conns = nil
}

func mongoConfig(addr string) config.Config {
	return config.Config{
		MongoURI:                    "mongodb://" + addr + "/?directConnection=true",
		MongoDB:                     "scanner_it",
		MongoConnectTimeout:         2 * time.Second,
		MongoServerSelectionTimeout: 2 * time.Second,
		MongoOperationTimeout:       5 * time.Second,
	}
}

func TestMongoClient(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}
	mongoAddr := startMongo(t)

	t.Run("reachable: up, and operations work with a deadline", func(t *testing.T) {
		client, err := store.NewClient(mongoConfig(mongoAddr))
		require.NoError(t, err)
		defer func() { _ = client.Disconnect(context.Background()) }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go client.Monitor(ctx, 100*time.Millisecond)

		require.Eventually(t, client.Up, 15*time.Second, 50*time.Millisecond)

		opCtx, opCancel := client.OperationContext(context.Background())
		defer opCancel()
		_, err = client.Database().Collection("it").InsertOne(opCtx, bson.M{"_id": "one", "value": 1})
		require.NoError(t, err)
		var doc bson.M
		require.NoError(t, client.Database().Collection("it").FindOne(opCtx, bson.M{"_id": "one"}).Decode(&doc))
		assert.EqualValues(t, 1, doc["value"])
	})

	t.Run("unreachable at startup: not up, no exit; comes back: up; goes away again: not up", func(t *testing.T) {
		proxy := newForwarder(t, mongoAddr)

		client, err := store.NewClient(mongoConfig(proxy.addr))
		require.NoError(t, err, "an unreachable Mongo is not a startup error")
		defer func() { _ = client.Disconnect(context.Background()) }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go client.Monitor(ctx, 100*time.Millisecond)

		time.Sleep(3 * time.Second) // longer than the server selection timeout
		assert.False(t, client.Up(), "readiness false while Mongo is unreachable")

		proxy.start(t)
		require.Eventually(t, client.Up, 30*time.Second, 50*time.Millisecond, "Mongo came back")

		proxy.stop()
		require.Eventually(t, func() bool { return !client.Up() }, 30*time.Second, 50*time.Millisecond, "Mongo went away")

		proxy.start(t)
		require.Eventually(t, client.Up, 30*time.Second, 50*time.Millisecond, "Mongo came back again")
	})
}
