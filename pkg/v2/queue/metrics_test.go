package queue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecent(t *testing.T) {
	q := &Queue{}
	assert.Equal(t, Recent{}, q.Recent())

	for i := 0; i < 25; i++ {
		q.metrics.scanFinished(i < 10) // ten failures first, then fifteen successes
	}

	assert.Equal(t, Recent{Done: 15, Failed: 5}, q.Recent(), "only the last 20 scans")
}

func TestPeekStatsNeverQueries(t *testing.T) {
	q := &Queue{} // no MongoDB client: a query would panic
	q.metrics.leaseLost()

	stats, known := q.PeekStats()

	assert.False(t, known, "no statistics read yet")
	assert.EqualValues(t, 1, stats.LeaseLosses, "the counters are live")
}
