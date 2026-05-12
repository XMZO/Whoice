package enrichment

import "testing"

func TestDefaultRegistryPricingAndMoz(t *testing.T) {
	registry := NewDefaultRegistry("")

	pricing, ok := registry.PricingForSuffix("COM")
	if !ok || pricing.Currency != "USD" || pricing.Register == nil {
		t.Fatalf("pricing: %#v ok=%t", pricing, ok)
	}

	moz, ok := registry.MozForDomain("www.example.com")
	if !ok || moz.DomainAuthority != 93 {
		t.Fatalf("moz: %#v ok=%t", moz, ok)
	}
}
