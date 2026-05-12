package pricing

import (
	"github.com/xmzo/whoice/services/lookup-api/internal/data/enrichment"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func Apply(result *model.LookupResult, registry *enrichment.Registry) {
	if result == nil || result.Type != model.QueryDomain {
		return
	}
	if registry == nil {
		registry = enrichment.NewDefaultRegistry("")
	}
	suffix := result.Domain.Suffix
	if suffix == "" {
		suffix = domainSuffix(result.NormalizedQuery)
	}
	info, ok := registry.PricingForSuffix(suffix)
	if !ok {
		return
	}
	result.Enrichment.Pricing = &info
}

func domainSuffix(domain string) string {
	for index, char := range domain {
		if char == '.' {
			return domain[index+1:]
		}
	}
	return domain
}
