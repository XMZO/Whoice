package plugin

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestRegisterDefaults(t *testing.T) {
	registry := NewRegistry()
	RegisterDefaults(registry, config.Config{
		AuthMode:         "none",
		RDAPEnabled:      true,
		WHOISEnabled:     true,
		WHOISWebEnabled:  false,
		EnrichEPP:        true,
		RateLimitEnabled: false,
	})

	if got := len(registry.Providers()); got != 3 {
		t.Fatalf("expected 3 providers, got %d", got)
	}
	if registry.ParserRegistry() == nil {
		t.Fatal("expected parser registry")
	}
	if got := len(registry.Plugins()); got < 6 {
		t.Fatalf("expected built-in plugin descriptors, got %d", got)
	}

	plugins := registry.Plugins()
	for _, want := range []string{
		"whois-tld-uk",
		"whois-tld-jp",
		"whois-tld-fr",
		"whois-tld-cn",
		"whois-tld-br",
		"whois-tld-it",
		"whois-tld-eu",
		"whois-tld-be",
		"whois-tld-pl",
		"whois-tld-cz",
		"whois-tld-hu",
		"whois-tld-sk",
		"whois-tld-ro",
		"whois-tld-de",
		"whois-tld-nl",
		"whois-tld-ca",
		"whois-tld-au",
		"whois-tld-se-nu",
		"whois-tld-fi",
		"whois-tld-kr",
		"whois-tld-at",
		"whois-tld-ru-su",
		"whois-tld-ee",
		"whois-tld-bg",
		"whois-tld-kg",
		"whois-tld-tr",
		"whois-tld-hk",
		"whois-tld-tw",
		"whois-tld-si",
		"whois-tld-ua",
		"whois-tld-id",
	} {
		if !hasPlugin(plugins, "parser", want) {
			t.Fatalf("expected parser plugin %s", want)
		}
	}
	if !hasPlugin(plugins, "provider", "whoisWeb") {
		t.Fatal("expected WHOIS Web provider descriptor")
	}
}

func hasPlugin(plugins []model.PluginInfo, kind, name string) bool {
	for _, plugin := range plugins {
		if plugin.Kind == kind && plugin.Name == name {
			return true
		}
	}
	return false
}
