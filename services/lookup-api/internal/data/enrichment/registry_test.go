package enrichment

import "testing"

func TestDefaultRegistryMoz(t *testing.T) {
	registry := NewDefaultRegistry("")

	moz, ok := registry.MozForDomain("www.example.com")
	if !ok || moz.DomainAuthority != 93 {
		t.Fatalf("moz: %#v ok=%t", moz, ok)
	}
}
