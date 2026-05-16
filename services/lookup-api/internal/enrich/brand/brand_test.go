package brand

import (
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/brandmap"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApplyDetectsRegistrarBrand(t *testing.T) {
	result := &model.LookupResult{
		Registrar: model.RegistrarInfo{
			Name: "Cloudflare, Inc.",
			URL:  "https://www.cloudflare.com",
		},
	}

	Apply(result, testRegistry(t))

	if result.Registrar.Brand == nil || result.Registrar.Brand.Slug != "cloudflare" {
		t.Fatalf("registrar brand: %#v", result.Registrar.Brand)
	}
	if result.Registrar.Brand.Logo == "" || result.Registrar.Brand.Website == "" {
		t.Fatalf("registrar brand metadata missing: %#v", result.Registrar.Brand)
	}
}

func TestApplyDetectsNameserverBrand(t *testing.T) {
	result := &model.LookupResult{
		Nameservers: []model.Nameserver{
			{Host: "ns-123.awsdns-45.com"},
			{Host: "ivan.ns.cloudflare.com"},
			{Host: "ns1.example.com"},
		},
	}

	Apply(result, testRegistry(t))

	if result.Nameservers[0].Brand == nil || result.Nameservers[0].Brand.Slug != "route53" {
		t.Fatalf("route53 brand: %#v", result.Nameservers[0].Brand)
	}
	if result.Nameservers[1].Brand == nil || result.Nameservers[1].Brand.Slug != "cloudflare" {
		t.Fatalf("cloudflare brand: %#v", result.Nameservers[1].Brand)
	}
	if result.Nameservers[2].Brand != nil {
		t.Fatalf("generic nameserver should not be branded: %#v", result.Nameservers[2].Brand)
	}
}

func TestApplyUsesMountedStyleRegistryRules(t *testing.T) {
	registry, err := brandmap.NewRegistryFromReader(strings.NewReader(`{
  "version": 1,
  "registrars": [
    {
      "name": "Example Registrar",
      "slug": "example-registrar",
      "color": "#123456",
      "logo": "https://example.test/logo.svg",
      "website": "https://registrar.example",
      "aliases": ["Example"],
      "patterns": ["example registrar"]
    }
  ],
  "nameservers": []
}`))
	if err != nil {
		t.Fatal(err)
	}
	result := &model.LookupResult{
		Registrar: model.RegistrarInfo{Name: "Example Registrar LLC"},
	}

	Apply(result, registry)

	if result.Registrar.Brand == nil || result.Registrar.Brand.Slug != "example-registrar" {
		t.Fatalf("custom brand: %#v", result.Registrar.Brand)
	}
	if result.Registrar.Brand.Logo != "https://example.test/logo.svg" || result.Registrar.Brand.Website != "https://registrar.example" {
		t.Fatalf("custom brand metadata: %#v", result.Registrar.Brand)
	}
}

func testRegistry(t *testing.T) *brandmap.Registry {
	t.Helper()
	registry, err := brandmap.NewSnapshotRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}
