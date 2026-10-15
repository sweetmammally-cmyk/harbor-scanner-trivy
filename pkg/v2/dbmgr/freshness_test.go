package dbmgr

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFreshness(t *testing.T) {
	now := time.Now()

	assert.Equal(t, FreshnessOK, Freshness(false, now.Add(-time.Hour), 3*time.Hour, now))
	assert.Equal(t, FreshnessOK, Freshness(false, now.Add(-3*time.Hour), 3*time.Hour, now), "exactly max age is still ok")
	assert.Equal(t, FreshnessStale, Freshness(false, now.Add(-4*time.Hour), 3*time.Hour, now))
	assert.Equal(t, FreshnessStale, Freshness(false, time.Time{}, 3*time.Hour, now), "never confirmed")
	assert.Equal(t, FreshnessStale, Freshness(true, now, 3*time.Hour, now), "newer available wins over max age")
}
