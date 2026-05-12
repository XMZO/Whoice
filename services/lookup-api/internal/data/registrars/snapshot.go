package registrars

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed snapshots/icann-accredited-registrars.csv
var snapshotFS embed.FS

func NewSnapshotRegistry() (*Registry, error) {
	body, err := snapshotFS.ReadFile("snapshots/icann-accredited-registrars.csv")
	if err != nil {
		return nil, err
	}
	registry, err := NewRegistryFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parse embedded registrar snapshot: %w", err)
	}
	return registry, nil
}

func NewDefaultRegistry(dataDir string) (*Registry, error) {
	if fileRegistry, err := NewFileRegistry(dataDir); err == nil {
		return fileRegistry, nil
	}
	return NewSnapshotRegistry()
}
