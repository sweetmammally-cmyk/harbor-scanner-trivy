package store_test

import (
	"testing"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/store/storetest"
)

func TestMemoryScans(t *testing.T) {
	storetest.ScanRepository(t, func(t *testing.T) store.ScanRepository { return store.NewMemoryScans() })
}

func TestMemoryPlatforms(t *testing.T) {
	storetest.PlatformRepository(t, func(t *testing.T) store.PlatformRepository { return store.NewMemoryPlatforms() })
}

func TestMemoryDBChecks(t *testing.T) {
	storetest.DBCheckRepository(t, func(t *testing.T) store.DBCheckRepository { return store.NewMemoryDBChecks() })
}

func TestMemoryReports(t *testing.T) {
	storetest.ReportStore(t, func(t *testing.T, limit int) store.ReportStore { return store.NewMemoryReports(limit) })
}
