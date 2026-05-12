package plugin

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
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
}
