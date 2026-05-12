package brandmap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Rule struct {
	Name     string   `json:"name"`
	Slug     string   `json:"slug,omitempty"`
	Color    string   `json:"color,omitempty"`
	Patterns []string `json:"patterns"`
}

type File struct {
	Version     int    `json:"version"`
	Description string `json:"description,omitempty"`
	Registrars  []Rule `json:"registrars"`
	Nameservers []Rule `json:"nameservers"`
}

type Registry struct {
	registrars  []Rule
	nameservers []Rule
}

func NewRegistryFromReader(reader io.Reader) (*Registry, error) {
	var file File
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	registry := &Registry{
		registrars:  cleanRules(file.Registrars),
		nameservers: cleanRules(file.Nameservers),
	}
	if len(registry.registrars) == 0 && len(registry.nameservers) == 0 {
		return nil, fmt.Errorf("brand map contains no usable rules")
	}
	return registry, nil
}

func NewFileRegistry(dataDir string) (*Registry, error) {
	for _, candidate := range fileCandidates(dataDir) {
		file, err := os.Open(candidate)
		if err != nil {
			continue
		}
		defer file.Close()
		registry, err := NewRegistryFromReader(file)
		if err != nil {
			return nil, fmt.Errorf("parse brand map %s: %w", candidate, err)
		}
		return registry, nil
	}
	return nil, fmt.Errorf("no brand map files found in %s", strings.TrimSpace(dataDir))
}

func (r *Registry) RegistrarRules() []Rule {
	if r == nil {
		return nil
	}
	items := make([]Rule, len(r.registrars))
	copy(items, r.registrars)
	return items
}

func (r *Registry) NameserverRules() []Rule {
	if r == nil {
		return nil
	}
	items := make([]Rule, len(r.nameservers))
	copy(items, r.nameservers)
	return items
}

func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.registrars) + len(r.nameservers)
}

func fileCandidates(dataDir string) []string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	return []string{
		filepath.Join(dataDir, "brands", "brand-map.json"),
		filepath.Join(dataDir, "brand-map.json"),
	}
}

func cleanRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Slug = strings.TrimSpace(rule.Slug)
		rule.Color = strings.TrimSpace(rule.Color)
		patterns := make([]string, 0, len(rule.Patterns))
		seen := map[string]bool{}
		for _, pattern := range rule.Patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" || seen[strings.ToLower(pattern)] {
				continue
			}
			patterns = append(patterns, pattern)
			seen[strings.ToLower(pattern)] = true
		}
		rule.Patterns = patterns
		if rule.Name == "" || len(rule.Patterns) == 0 {
			continue
		}
		out = append(out, rule)
	}
	return out
}
