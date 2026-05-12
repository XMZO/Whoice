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
	pricing map[string]model.PricingInfo
	moz     map[string]model.MozInfo
}

func NewDefaultRegistry(dataDir string) *Registry {
	registry := &Registry{
		pricing: map[string]model.PricingInfo{},
		moz:     map[string]model.MozInfo{},
	}
	_ = registry.loadPricing(readSnapshot("pricing.json"))
	_ = registry.loadMoz(readSnapshot("moz.json"))
	if dataDir != "" {
		for _, path := range []string{
			filepath.Join(dataDir, "enrichment", "pricing.json"),
			filepath.Join(dataDir, "pricing.json"),
		} {
			if body, err := os.ReadFile(path); err == nil {
				_ = registry.loadPricing(body, true)
				break
			}
		}
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

func (r *Registry) PricingForSuffix(suffix string) (model.PricingInfo, bool) {
	if r == nil {
		return model.PricingInfo{}, false
	}
	value, ok := r.pricing[normalizeKey(suffix)]
	return value, ok
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

func (r *Registry) loadPricing(body []byte, replace ...bool) error {
	if len(body) == 0 {
		return nil
	}
	var file struct {
		Currency string                       `json:"currency"`
		Source   string                       `json:"source"`
		TLDs     map[string]model.PricingInfo `json:"tlds"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		return fmt.Errorf("parse pricing data: %w", err)
	}
	if len(replace) > 0 && replace[0] {
		r.pricing = map[string]model.PricingInfo{}
	}
	for suffix, value := range file.TLDs {
		key := normalizeKey(suffix)
		if key == "" {
			continue
		}
		if value.Currency == "" {
			value.Currency = file.Currency
		}
		if value.Source == "" {
			value.Source = file.Source
		}
		r.pricing[key] = value
	}
	return nil
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
