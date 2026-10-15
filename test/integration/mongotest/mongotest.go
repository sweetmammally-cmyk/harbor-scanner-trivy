//go:build integration

// Package mongotest starts a MongoDB for integration tests.
package mongotest

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
)

// StartContainer starts a mongo:7 container and returns its host:port and a
// function that stops it. For TestMain, so a package shares one container.
func StartContainer() (string, func(), error) {
	ctx := context.Background()
	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "mongo:7",
			ExposedPorts: []string{"27017/tcp"},
			WaitingFor:   wait.ForListeningPort("27017/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return "", nil, fmt.Errorf("starting mongo container: %w", err)
	}
	stop := func() { _ = container.Terminate(ctx) }
	host, err := container.Host(ctx)
	if err != nil {
		stop()
		return "", nil, err
	}
	port, err := container.MappedPort(ctx, "27017")
	if err != nil {
		stop()
		return "", nil, err
	}
	return net.JoinHostPort(host, port.Port()), stop, nil
}

var databases atomic.Int32

// Config returns a v2 config for MongoDB at addr with a new database name.
func Config(addr string) config.Config {
	return config.Config{
		MongoURI:                    "mongodb://" + addr + "/?directConnection=true",
		MongoDB:                     fmt.Sprintf("it_%d", databases.Add(1)),
		MongoConnectTimeout:         2 * time.Second,
		MongoServerSelectionTimeout: 2 * time.Second,
		MongoOperationTimeout:       5 * time.Second,
		DBChecksRetention:           24 * time.Hour,
		DBStateRetention:            24 * time.Hour,
	}
}

// Client returns a client for cfg with the schema ensured. Several clients on
// the same config act as several scanner replicas.
func Client(t *testing.T, cfg config.Config) *store.Client {
	client, err := store.NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	require.NoError(t, client.EnsureSchema(context.Background()))
	return client
}
