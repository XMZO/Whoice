package brandmap

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed snapshots/brand-map.json
var snapshotFS embed.FS

func NewSnapshotRegistry() (*Registry, error) {
	body, err := snapshotFS.ReadFile("snapshots/brand-map.json")
	if err != nil {
		return nil, err
	}
	registry, err := NewRegistryFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse embedded brand map snapshot: %w", err)
	}
	return registry, nil
}

func NewDefaultRegistry(dataDir string) (*Registry, error) {
	if fileRegistry, err := NewFileRegistry(dataDir); err == nil {
		return fileRegistry, nil
	}
	return NewSnapshotRegistry()
}
