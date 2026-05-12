package moz

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
	domain := result.Domain.RegisteredDomain
	if domain == "" {
		domain = result.NormalizedQuery
	}
	info, ok := registry.MozForDomain(domain)
	if !ok {
		return
	}
	result.Enrichment.Moz = &info
}
