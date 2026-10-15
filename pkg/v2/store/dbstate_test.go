package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/dbmgr"
)

// unreachableStore is a DBStateStore whose MongoDB never answers.
func unreachableStore(t *testing.T) *DBStateStore {
	client, err := NewClient(testConfig("mongodb://127.0.0.1:1/?directConnection=true"))
	require.NoError(t, err)
	return NewDBStateStore(client, "scanner-1")
}

// runState is a DB state as after a run with one source per minute in minutes.
func runState(mode string, minutes ...int) dbmgr.DBState {
	state := dbmgr.DBState{Mode: mode}
	for _, minute := range minutes {
		state.LastSources = append(state.LastSources, dbmgr.SourceResult{
			Source:   fmt.Sprintf("mirror-%d|direct", minute),
			Precheck: dbmgr.CheckResult{StartedAt: at.Add(time.Duration(minute) * time.Minute)},
		})
	}
	return state
}

func checkMinutes(checks []DBCheck) []int {
	var minutes []int
	for _, check := range checks {
		minutes = append(minutes, int(check.At.Sub(at)/time.Minute))
	}
	return minutes
}

func TestDBStateStore_MemoryFirst(t *testing.T) {
	s := unreachableStore(t)

	start := time.Now()
	require.NoError(t, s.Save(context.Background(), "db", runState(dbmgr.ModeNormal, 1)))
	assert.Less(t, time.Since(start), 100*time.Millisecond, "Save does not wait for an unreachable MongoDB")

	state, err := s.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, dbmgr.ModeNormal, state.Mode)
	javaState, err := s.Get(context.Background(), "java-db")
	require.NoError(t, err)
	assert.Equal(t, dbmgr.DBState{}, javaState)
	assert.True(t, s.unwritten["db"], "written when MongoDB is back")
	require.Len(t, s.buffer, 1)
	assert.Equal(t, "scanner-1", s.buffer[0].InstanceID)
	assert.Equal(t, "db", s.buffer[0].DB)
}

func TestDBStateStore_BufferDropsOldest(t *testing.T) {
	s := unreachableStore(t)
	s.maxChecks = 3

	require.NoError(t, s.Save(context.Background(), "db", runState(dbmgr.ModeDegraded, 1, 2)))
	require.NoError(t, s.Save(context.Background(), "db", runState(dbmgr.ModeDegraded, 3, 4)))

	assert.Equal(t, []int{2, 3, 4}, checkMinutes(s.buffer))
	assert.Equal(t, 1, s.dropped)
}

func TestDBStateStore_FailedFlushKeepsEverything(t *testing.T) {
	s := unreachableStore(t)
	s.maxChecks = 3
	require.NoError(t, s.Save(context.Background(), "db", runState(dbmgr.ModeDegraded, 1, 2, 3, 4)))
	logs := captureLogs(t)

	s.Flush(context.Background())

	assert.Contains(t, logs.String(), `"msg":"db_checks were dropped while MongoDB was down, the buffer was full","dropped":1,"buffer_size":3`)
	assert.Contains(t, logs.String(), "writing DB state to MongoDB failed, will retry")
	assert.Contains(t, logs.String(), "writing db_checks to MongoDB failed, will retry")
	assert.True(t, s.unwritten["db"], "the state is written by a later Flush")
	assert.Equal(t, []int{2, 3, 4}, checkMinutes(s.buffer), "the checks stay, in order")
	assert.Equal(t, 0, s.dropped, "the dropped count was logged")

	// Checks of a run that happened during the failed flush come after the old ones.
	require.NoError(t, s.Save(context.Background(), "db", runState(dbmgr.ModeDegraded, 5)))
	assert.Equal(t, []int{3, 4, 5}, checkMinutes(s.buffer))
}

func TestDBStateStore_UpdaterKeepsRunningWhileMongoIsDown(t *testing.T) {
	s := unreachableStore(t)
	cfg := config.Config{} // no DB sources: each run ends degraded at once
	updater := dbmgr.NewUpdater(context.Background(), cfg, t.TempDir(), s)

	for run := 0; run < 3; run++ {
		start := time.Now()
		results, err := updater.UpdateNow(context.Background())
		require.NoError(t, err)
		assert.Less(t, time.Since(start), time.Second, "a run does not wait for MongoDB")
		assert.Equal(t, dbmgr.ModeDegraded, results.DB.Mode)
	}

	state, err := s.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, dbmgr.ModeDegraded, state.Mode, "the state is kept in memory")
}

// writtenButFailing is a DBCheckRepository that keeps every row but reports an
// error on its first Add, like a write that reached MongoDB before a timeout.
type writtenButFailing struct {
	MemoryDBChecks
	adds int
}

func (w *writtenButFailing) Add(ctx context.Context, checks []DBCheck) error {
	w.adds++
	_ = w.MemoryDBChecks.Add(ctx, checks)
	if w.adds == 1 {
		return errors.New("timeout after the write")
	}
	return nil
}

func TestDBStateStore_FlushTwiceDoesNotDuplicateChecks(t *testing.T) {
	s := unreachableStore(t)
	repository := &writtenButFailing{}
	s.checks = repository
	require.NoError(t, s.Save(context.Background(), "db", runState(dbmgr.ModeDegraded, 1, 2)))

	s.Flush(context.Background()) // rows written, but reported as failed: buffered again
	require.Len(t, s.buffer, 2)
	s.Flush(context.Background()) // the same rows again, with the same ids

	assert.Equal(t, 2, repository.adds)
	rows, err := repository.Recent(context.Background(), "db", 10)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "the second flush replaced the rows instead of adding copies")
	// Both rows carry the run start (the first source's pre-check start), newest first.
	runStart := at.Add(time.Minute).Format(time.RFC3339Nano)
	assert.Equal(t, "scanner-1:db:"+runStart+":mirror-2|direct", rows[0].ID)
	assert.Equal(t, "scanner-1:db:"+runStart+":mirror-1|direct", rows[1].ID)
}
