//go:build integration

package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store/storetest"
)

var databaseCounter atomic.Int32

// freshClient returns a client on a new, empty database with the schema ensured.
func freshClient(t *testing.T, mongoAddr string) *store.Client {
	name := fmt.Sprintf("repo_%d", databaseCounter.Add(1))
	client := newClient(t, schemaConfig(mongoAddr, name, 24*time.Hour))
	require.NoError(t, client.EnsureSchema(context.Background()))
	return client
}

func TestMongoRepositories(t *testing.T) {
	if testing.Short() {
		t.Skip("An integration test")
	}
	mongoAddr := startMongo(t)

	t.Run("scans", func(t *testing.T) {
		storetest.ScanRepository(t, func(t *testing.T) store.ScanRepository {
			return store.NewMongoScans(freshClient(t, mongoAddr))
		})
	})
	t.Run("platforms", func(t *testing.T) {
		storetest.PlatformRepository(t, func(t *testing.T) store.PlatformRepository {
			return store.NewMongoPlatforms(freshClient(t, mongoAddr))
		})
	})
	t.Run("db_checks", func(t *testing.T) {
		storetest.DBCheckRepository(t, func(t *testing.T) store.DBCheckRepository {
			return store.NewMongoDBChecks(freshClient(t, mongoAddr))
		})
	})

	t.Run("concurrent first sightings of a platform all count", func(t *testing.T) {
		repository := store.NewMongoPlatforms(freshClient(t, mongoAddr))
		var wg sync.WaitGroup
		errs := make([]error, 10)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = repository.Seen(context.Background(), []string{"pip"}, "sha256:x", time.Now())
			}()
		}
		wg.Wait()

		for _, err := range errs {
			require.NoError(t, err)
		}
		platforms, err := repository.List(context.Background())
		require.NoError(t, err)
		require.Len(t, platforms, 1)
		assert.EqualValues(t, 10, platforms[0].SeenCount)
	})
}
