package dbmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Metadata is Trivy's metadata.json, shipped next to trivy.db and trivy-java.db.
// Example: {"Version":2,"NextUpdate":"...","UpdatedAt":"...","DownloadedAt":"..."}
type Metadata struct {
	Version      int       `json:"Version"`
	NextUpdate   time.Time `json:"NextUpdate"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DownloadedAt time.Time `json:"DownloadedAt"`
}

// readMetadata reads metadata.json from a DB directory. UpdatedAt is required,
// because the scan cache and the DB age depend on it.
func readMetadata(dir string) (Metadata, error) {
	data, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return Metadata{}, fmt.Errorf("reading DB metadata: %w", err)
	}

	var metadata Metadata
	if err = json.Unmarshal(data, &metadata); err != nil {
		return Metadata{}, fmt.Errorf("decoding DB metadata in %s: %w", dir, err)
	}
	if metadata.UpdatedAt.IsZero() {
		return Metadata{}, fmt.Errorf("DB metadata in %s has no UpdatedAt", dir)
	}
	return metadata, nil
}
