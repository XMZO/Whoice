package registrars

import (
	"strings"
	"testing"
)

func TestRegistryFindsByIANAIDAndName(t *testing.T) {
	registry, err := NewRegistryFromReader(strings.NewReader(`"Registrar Name","IANA Number","Country/Territory","Public Contact","Link"
"Cloudflare, Inc.",1910,"United States of America","Registrar Public","http://www.cloudflare.com"
`))
	if err != nil {
		t.Fatal(err)
	}

	byID, ok := registry.FindByIANAID("1910")
	if !ok || byID.URL != "http://www.cloudflare.com" {
		t.Fatalf("by id: %#v ok=%t", byID, ok)
	}

	byName, ok := registry.FindByName("Cloudflare Inc")
	if !ok || byName.IANAID != "1910" {
		t.Fatalf("by name: %#v ok=%t", byName, ok)
	}
}

func TestSnapshotRegistryLoads(t *testing.T) {
	registry, err := NewSnapshotRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.Len() == 0 {
		t.Fatal("expected embedded registrar rows")
	}
	if item, ok := registry.FindByIANAID("1910"); !ok || item.Name == "" {
		t.Fatalf("missing cloudflare snapshot row: %#v ok=%t", item, ok)
	}
}
