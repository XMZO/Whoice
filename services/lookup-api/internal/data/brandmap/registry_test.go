package brandmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryLoadsRules(t *testing.T) {
	registry, err := NewRegistryFromReader(strings.NewReader(`{
  "version": 1,
  "registrars": [
    {
      "name": "Cloudflare",
      "slug": "cloudflare",
      "color": "#f6821f",
      "logo": "https://example.test/cloudflare.svg",
      "website": "https://www.cloudflare.com",
      "aliases": ["CF"],
      "patterns": ["cloudflare", "Cloudflare"]
    }
  ],
  "nameservers": [
    { "name": "Route 53", "slug": "route53", "patterns": [".awsdns-"] }
  ]
}`))
	if err != nil {
		t.Fatal(err)
	}

	if got := registry.Len(); got != 2 {
		t.Fatalf("len: got %d want 2", got)
	}
	if got := len(registry.RegistrarRules()[0].Patterns); got != 1 {
		t.Fatalf("deduped patterns: got %d want 1", got)
	}
	rule := registry.RegistrarRules()[0]
	if rule.Logo == "" || rule.Website == "" || len(rule.Aliases) != 1 {
		t.Fatalf("brand metadata was not preserved: %#v", rule)
	}
}

func TestFileRegistryPrefersMountedBrandMap(t *testing.T) {
	dir := t.TempDir()
	brandDir := filepath.Join(dir, "brands")
	if err := os.MkdirAll(brandDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "version": 1,
  "registrars": [
    { "name": "Mounted Registrar", "slug": "mounted", "patterns": ["mounted"] }
  ],
  "nameservers": []
}`
	if err := os.WriteFile(filepath.Join(brandDir, "brand-map.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	registry, err := NewFileRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	rules := registry.RegistrarRules()
	if len(rules) != 1 || rules[0].Slug != "mounted" {
		t.Fatalf("mounted rules: %#v", rules)
	}
}

func TestSnapshotRegistryLoads(t *testing.T) {
	registry, err := NewSnapshotRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.Len() == 0 {
		t.Fatal("expected embedded brand map rules")
	}
}
