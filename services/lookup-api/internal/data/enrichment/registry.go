package enrichment

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

//go:embed snapshots/*.json
var snapshotFS embed.FS

type Registry struct {
	moz map[string]model.MozInfo
}

func NewDefaultRegistry(dataDir string) *Registry {
	registry := &Registry{
		moz: map[string]model.MozInfo{},
	}
	_ = registry.loadMoz(readSnapshot("moz.json"))
	if dataDir != "" {
		for _, path := range []string{
			filepath.Join(dataDir, "enrichment", "moz.json"),
			filepath.Join(dataDir, "moz.json"),
		} {
			if body, err := os.ReadFile(path); err == nil {
				_ = registry.loadMoz(body, true)
				break
			}
		}
	}
	return registry
}

func (r *Registry) MozForDomain(domain string) (model.MozInfo, bool) {
	if r == nil {
		return model.MozInfo{}, false
	}
	domain = normalizeKey(domain)
	for domain != "" {
		if value, ok := r.moz[domain]; ok {
			return value, true
		}
		_, rest, ok := strings.Cut(domain, ".")
		if !ok {
			break
		}
		domain = rest
	}
	return model.MozInfo{}, false
}

func readSnapshot(name string) []byte {
	body, err := snapshotFS.ReadFile("snapshots/" + name)
	if err != nil {
		return nil
	}
	return body
}

func (r *Registry) loadMoz(body []byte, replace ...bool) error {
	if len(body) == 0 {
		return nil
	}
	var file struct {
		Domains map[string]model.MozInfo `json:"domains"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		return fmt.Errorf("parse moz data: %w", err)
	}
	if len(replace) > 0 && replace[0] {
		r.moz = map[string]model.MozInfo{}
	}
	for domain, value := range file.Domains {
		key := normalizeKey(domain)
		if key == "" {
			continue
		}
		if value.UpdatedAt == "" {
			value.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		r.moz[key] = value
	}
	return nil
}

func normalizeKey(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
}
