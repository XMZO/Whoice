package pricing

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/enrichment"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApply(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
		Domain:          model.DomainInfo{Suffix: "com"},
	}

	Apply(result, enrichment.NewDefaultRegistry(""))

	if result.Enrichment.Pricing == nil || result.Enrichment.Pricing.Currency != "USD" {
		t.Fatalf("pricing: %#v", result.Enrichment.Pricing)
	}
}
