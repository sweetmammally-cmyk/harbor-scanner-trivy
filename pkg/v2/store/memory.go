package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// The memory repositories are fakes for unit tests of the packages that use the
// store. They follow the same contract as the MongoDB repositories (see storetest).

// MemoryScans is an in-memory ScanRepository.
type MemoryScans struct {
	mu    sync.Mutex
	scans map[string]Scan
}

func NewMemoryScans() *MemoryScans {
	return &MemoryScans{scans: map[string]Scan{}}
}

func (m *MemoryScans) Create(_ context.Context, scan Scan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, found := m.scans[scan.ID]; found {
		return fmt.Errorf("scan %s already exists", scan.ID)
	}
	for _, existing := range m.scans {
		if scan.RequestID != "" && existing.RequestID == scan.RequestID {
			return ErrDuplicateRequestID
		}
	}
	m.scans[scan.ID] = scan
	return nil
}

func (m *MemoryScans) Get(_ context.Context, id string) (Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	scan, found := m.scans[id]
	if !found {
		return Scan{}, ErrNotFound
	}
	return scan, nil
}

func (m *MemoryScans) GetByRequestID(_ context.Context, requestID string) (Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, scan := range m.scans {
		if requestID != "" && scan.RequestID == requestID {
			return scan, nil
		}
	}
	return Scan{}, ErrNotFound
}

func (m *MemoryScans) LastDone(_ context.Context, digest string) (Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last Scan
	found := false
	for _, scan := range m.scans {
		if scan.Image.Digest != digest || scan.State != ScanDone || scan.FinishedAt == nil {
			continue
		}
		if !found || scan.FinishedAt.After(*last.FinishedAt) {
			last = scan
			found = true
		}
	}
	if !found {
		return Scan{}, ErrNotFound
	}
	return last, nil
}

// MemoryPlatforms is an in-memory PlatformRepository.
type MemoryPlatforms struct {
	mu        sync.Mutex
	platforms map[string]Platform
}

func NewMemoryPlatforms() *MemoryPlatforms {
	return &MemoryPlatforms{platforms: map[string]Platform{}}
}

func (m *MemoryPlatforms) Seen(_ context.Context, types []string, digest string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, platformType := range types {
		platform, found := m.platforms[platformType]
		if !found {
			platform = Platform{ID: platformType, FirstSeenAt: at, ExampleDigest: digest}
		}
		platform.LastSeenAt = at
		platform.SeenCount++
		m.platforms[platformType] = platform
	}
	return nil
}

func (m *MemoryPlatforms) List(_ context.Context) ([]Platform, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var platforms []Platform
	for _, platform := range m.platforms {
		platforms = append(platforms, platform)
	}
	sort.Slice(platforms, func(i, j int) bool { return platforms[i].ID < platforms[j].ID })
	return platforms, nil
}

// MemoryDBChecks is an in-memory DBCheckRepository. It does not expire documents.
type MemoryDBChecks struct {
	mu     sync.Mutex
	checks []DBCheck
}

func NewMemoryDBChecks() *MemoryDBChecks {
	return &MemoryDBChecks{}
}

// Add replaces checks with the same ID, like the MongoDB upsert.
func (m *MemoryDBChecks) Add(_ context.Context, checks []DBCheck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, check := range checks {
		replaced := false
		for i := range m.checks {
			if m.checks[i].ID == check.ID {
				m.checks[i] = check
				replaced = true
			}
		}
		if !replaced {
			m.checks = append(m.checks, check)
		}
	}
	return nil
}

func (m *MemoryDBChecks) Recent(_ context.Context, db string, limit int) ([]DBCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var checks []DBCheck
	for _, check := range m.checks {
		if check.DB == db {
			checks = append(checks, check)
		}
	}
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].At.After(checks[j].At) })
	if len(checks) > limit {
		checks = checks[:limit]
	}
	return checks, nil
}
