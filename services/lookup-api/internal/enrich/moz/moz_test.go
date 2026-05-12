package moz

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/enrichment"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApply(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "www.example.com",
		Type:            model.QueryDomain,
		Domain:          model.DomainInfo{RegisteredDomain: "example.com"},
	}

	Apply(result, enrichment.NewDefaultRegistry(""))

	if result.Enrichment.Moz == nil || result.Enrichment.Moz.DomainAuthority != 93 {
		t.Fatalf("moz: %#v", result.Enrichment.Moz)
	}
}
