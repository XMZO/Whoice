package dnsviz

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApplyAddsDNSVizURLForDomains(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
		Domain:          model.DomainInfo{Name: "example.com"},
	}

	Apply(result)

	if result.Enrichment.DNSViz == nil {
		t.Fatal("expected dnsviz enrichment")
	}
	if got, want := result.Enrichment.DNSViz.URL, "https://dnsviz.net/d/example.com/dnssec/"; got != want {
		t.Fatalf("url: got %q want %q", got, want)
	}
}

func TestApplySkipsNonDomains(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "1.1.1.1",
		Type:            model.QueryIPv4,
	}

	Apply(result)

	if result.Enrichment.DNSViz != nil {
		t.Fatal("expected no dnsviz enrichment")
	}
}
