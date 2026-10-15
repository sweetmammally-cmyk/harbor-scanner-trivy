package dbmgr

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitForContext is a stage that only ends when its context ends.
func waitForContext(ctx context.Context) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func TestRunStage(t *testing.T) {
	t.Run("passing stage records its detail and duration", func(t *testing.T) {
		var result CheckResult
		ok := runStage(context.Background(), &result, "tls", time.Second, func(ctx context.Context) (string, error) {
			time.Sleep(10 * time.Millisecond)
			return "TLS 1.3", nil
		})

		assert.True(t, ok)
		require.Len(t, result.Stages, 1)
		assert.Equal(t, "tls", result.Stages[0].Stage)
		assert.True(t, result.Stages[0].OK)
		assert.Equal(t, "TLS 1.3", result.Stages[0].Detail)
		assert.GreaterOrEqual(t, result.Stages[0].Duration, 10*time.Millisecond)
	})

	t.Run("failing stage records the error", func(t *testing.T) {
		var result CheckResult
		ok := runStage(context.Background(), &result, "http", time.Second, func(ctx context.Context) (string, error) {
			return "", errors.New("status 500")
		})

		assert.False(t, ok)
		require.Len(t, result.Stages, 1)
		assert.False(t, result.Stages[0].OK)
		assert.Equal(t, "status 500", result.Stages[0].Detail)
	})

	t.Run("stage stops at its own timeout", func(t *testing.T) {
		var result CheckResult
		start := time.Now()
		ok := runStage(context.Background(), &result, "connect", 50*time.Millisecond, waitForContext)

		assert.False(t, ok)
		assert.Less(t, time.Since(start), time.Second)
		assert.Equal(t, "stage timeout 50ms exceeded: context deadline exceeded", result.Stages[0].Detail)
	})

	t.Run("overall deadline cuts a stage with a longer timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		var result CheckResult
		start := time.Now()
		ok := runStage(ctx, &result, "manifest", time.Minute, waitForContext)

		assert.False(t, ok)
		assert.Less(t, time.Since(start), time.Second)
		assert.Equal(t, "overall pre-check deadline exceeded: context deadline exceeded", result.Stages[0].Detail)
	})

	t.Run("stages are appended in order", func(t *testing.T) {
		var result CheckResult
		pass := func(ctx context.Context) (string, error) { return "", nil }
		runStage(context.Background(), &result, "dns", time.Second, pass)
		runStage(context.Background(), &result, "connect", time.Second, pass)

		require.Len(t, result.Stages, 2)
		assert.Equal(t, "dns", result.Stages[0].Stage)
		assert.Equal(t, "connect", result.Stages[1].Stage)
	})
}
