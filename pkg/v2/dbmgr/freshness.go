package dbmgr

import "time"

const (
	FreshnessOK    = "ok"
	FreshnessStale = "stale"
)

// Freshness is the db.freshness of API responses (DEMAND section 7.4): stale while
// a newer DB is known but not installed, otherwise ok when the DB was confirmed
// current within maxAge.
func Freshness(newerAvailable bool, confirmedCurrentAt time.Time, maxAge time.Duration, now time.Time) string {
	if newerAvailable || confirmedCurrentAt.IsZero() {
		return FreshnessStale
	}
	if now.Sub(confirmedCurrentAt) > maxAge {
		return FreshnessStale
	}
	return FreshnessOK
}
