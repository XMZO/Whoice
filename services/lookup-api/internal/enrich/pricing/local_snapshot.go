package pricing

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

//go:embed snapshots/*.json
var snapshotFS embed.FS

type LocalSnapshotSource struct {
	pricing map[string]model.PricingInfo
}

func NewLocalSnapshotSource(dataDir string) *LocalSnapshotSource {
	source := &LocalSnapshotSource{pricing: map[string]model.PricingInfo{}}
	_ = source.load(readSnapshot("pricing.json"))
	if dataDir != "" {
		for _, path := range []string{
			filepath.Join(dataDir, "pricing", "pricing.json"),
			filepath.Join(dataDir, "pricing.json"),
			// Legacy path kept so existing compose mounts continue to work.
			filepath.Join(dataDir, "enrichment", "pricing.json"),
		} {
			if body, err := os.ReadFile(path); err == nil {
				_ = source.load(body, true)
				break
			}
		}
	}
	return source
}

func (s *LocalSnapshotSource) Name() string {
	return "local-snapshot"
}

func (s *LocalSnapshotSource) Lookup(_ context.Context, suffix string) (model.PricingInfo, bool, error) {
	if s == nil {
		return model.PricingInfo{}, false, nil
	}
	value, ok := s.pricing[normalizeSuffix(suffix)]
	return value, ok, nil
}

func readSnapshot(name string) []byte {
	body, err := snapshotFS.ReadFile("snapshots/" + name)
	if err != nil {
		return nil
	}
	return body
}

func (s *LocalSnapshotSource) load(body []byte, replace ...bool) error {
	if len(body) == 0 {
		return nil
	}
	var file struct {
		Currency  string                       `json:"currency"`
		Source    string                       `json:"source"`
		Provider  string                       `json:"provider"`
		UpdatedAt string                       `json:"updatedAt"`
		TLDs      map[string]model.PricingInfo `json:"tlds"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		return fmt.Errorf("parse pricing data: %w", err)
	}
	if len(replace) > 0 && replace[0] {
		s.pricing = map[string]model.PricingInfo{}
	}
	for suffix, value := range file.TLDs {
		key := normalizeSuffix(suffix)
		if key == "" {
			continue
		}
		if value.Currency == "" {
			value.Currency = file.Currency
		}
		if value.Source == "" {
			value.Source = file.Source
		}
		if value.Provider == "" {
			value.Provider = file.Provider
		}
		if value.Provider == "" {
			value.Provider = file.Source
		}
		if value.UpdatedAt == "" {
			value.UpdatedAt = file.UpdatedAt
		}
		fillLegacyOffers(&value)
		s.pricing[key] = value
	}
	return nil
}

func fillLegacyOffers(info *model.PricingInfo) {
	if info == nil {
		return
	}
	if info.RegisterOffer == nil && info.Register != nil {
		info.RegisterOffer = legacyOffer(info.Register, info.Currency, info.Provider)
	}
	if info.RenewOffer == nil && info.Renew != nil {
		info.RenewOffer = legacyOffer(info.Renew, info.Currency, info.Provider)
	}
	if info.TransferOffer == nil && info.Transfer != nil {
		info.TransferOffer = legacyOffer(info.Transfer, info.Currency, info.Provider)
	}
}

func legacyOffer(price *float64, currency, provider string) *model.PricingOffer {
	value := *price
	return &model.PricingOffer{
		Registrar: provider,
		Price:     &value,
		Currency:  currency,
	}
}
