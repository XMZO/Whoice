package publicsuffixes

import (
	"strings"
	"testing"
)

func TestRulesPublicSuffix(t *testing.T) {
	rules := NewRules()
	if err := rules.Merge(strings.NewReader(`
// comments are ignored
de5.net
*.example
!city.example
`)); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"www.de5.net":          "de5.net",
		"api.customer.example": "customer.example",
		"www.city.example":     "example",
	}
	for input, want := range tests {
		got, ok := rules.PublicSuffix(input)
		if !ok || got != want {
			t.Fatalf("%s: got %q ok=%t want %q", input, got, ok, want)
		}
	}
}

func TestEffectiveTLDPlusOne(t *testing.T) {
	if got := EffectiveTLDPlusOne("www.de5.net", "de5.net"); got != "www.de5.net" {
		t.Fatalf("got %q", got)
	}
	if got := EffectiveTLDPlusOne("de5.net", "de5.net"); got != "" {
		t.Fatalf("public suffix should not have registrable domain, got %q", got)
	}
}
