package registrar

import (
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/registrars"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApplyFillsMissingRegistrarFields(t *testing.T) {
	registry, err := registrars.NewRegistryFromReader(strings.NewReader(`"Registrar Name","IANA Number","Country/Territory","Public Contact","Link"
"Cloudflare, Inc.",1910,"United States of America","Registrar Public","http://www.cloudflare.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	result := &model.LookupResult{
		Type:      model.QueryDomain,
		Registrar: model.RegistrarInfo{IANAID: "1910"},
	}
	Apply(result, registry)

	if result.Registrar.Name != "Cloudflare, Inc." {
		t.Fatalf("name: %q", result.Registrar.Name)
	}
	if result.Registrar.URL != "http://www.cloudflare.com" {
		t.Fatalf("url: %q", result.Registrar.URL)
	}
	if result.Registrar.Country != "United States of America" {
		t.Fatalf("country: %q", result.Registrar.Country)
	}
}

func TestApplyMatchesByNormalizedName(t *testing.T) {
	registry, err := registrars.NewRegistryFromReader(strings.NewReader(`"Registrar Name","IANA Number","Country/Territory","Public Contact","Link"
"NameCheap, Inc.",1068,"United States of America","Registrar Support","http://www.namecheap.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	result := &model.LookupResult{
		Type:      model.QueryDomain,
		Registrar: model.RegistrarInfo{Name: "NameCheap Inc"},
	}
	Apply(result, registry)

	if result.Registrar.IANAID != "1068" {
		t.Fatalf("iana id: %q", result.Registrar.IANAID)
	}
}
