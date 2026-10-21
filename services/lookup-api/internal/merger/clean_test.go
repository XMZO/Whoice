package merger

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestDecodeUnicodeEscapes(t *testing.T) {
	for input, want := range map[string]string{
		`\u0130zmir`:                   "İzmir",
		`Istanbul`:                     "Istanbul",
		`\u00c7ankaya \u015ei\u015fli`: "Çankaya Şişli",
		`\ud83d\ude00 smile`:           "😀 smile",
		`\u0000bad`:                    `\u0000bad`,
		`\u12`:                         `\u12`,
		`C:\users\name`:                `C:\users\name`,
	} {
		if got := decodeUnicodeEscapes(input); got != want {
			t.Fatalf("decodeUnicodeEscapes(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCleanContactValueDropsPlaceholdersOnly(t *testing.T) {
	for input, want := range map[string]string{
		"REDACTED":             "",
		"REDACTED REDACTED":    "",
		"REDACTED, REDACTED":   "",
		"Redacted for Privacy": "",
		"<not disclosed>":      "",
		"Data Protected":       "",
		"apeiria.io":           "apeiria.io",
		"Redacted Studio Ltd":  "Redacted Studio Ltd",
		`\u0130zmir`:           "İzmir",
	} {
		if got := cleanContactValue(input); got != want {
			t.Fatalf("cleanContactValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestMergeKeepsRealValueOverRedactedPlaceholder(t *testing.T) {
	q := model.NormalizedQuery{Type: model.QueryDomain, Query: "apeiria.io"}
	whois := &model.PartialResult{Source: model.SourceWHOIS, Status: model.StatusRegistered, Registrant: model.RegistrantInfo{Name: "REDACTED", City: `\u0130zmir`, Province: "REDACTED", Address: "REDACTED REDACTED"}}
	rdap := &model.PartialResult{Source: model.SourceRDAP, Status: model.StatusRegistered, Registrant: model.RegistrantInfo{Name: "Apeiria", Organization: "apeiria.io"}}
	result := New().Merge(q, []*model.PartialResult{whois, rdap})
	r := result.Registrant
	if r.Name != "Apeiria" || r.City != "İzmir" || r.Province != "" || r.Address != "" || r.Organization != "apeiria.io" {
		t.Fatalf("registrant: %#v", r)
	}
	for key, sources := range r.FieldSources {
		for _, source := range sources {
			if source.Value == "REDACTED" {
				t.Fatalf("placeholder kept in field sources for %s", key)
			}
		}
	}
}
