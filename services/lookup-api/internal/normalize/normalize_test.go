package normalize

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestNormalizeDomainURL(t *testing.T) {
	n := New()
	got, err := n.Normalize("https://www.Example.COM/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Query != "www.example.com" || got.Type != model.QueryDomain {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestNormalizeIPAndCIDR(t *testing.T) {
	n := New()
	cases := map[string]model.QueryType{
		"8.8.8.8":      model.QueryIPv4,
		"2001:4860::1": model.QueryIPv6,
		"1.1.1.0/24":   model.QueryCIDR,
	}
	for input, queryType := range cases {
		got, err := n.Normalize(input)
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != queryType {
			t.Fatalf("%s: expected %s, got %s", input, queryType, got.Type)
		}
	}
}

func TestNormalizeASN(t *testing.T) {
	n := New()
	got, err := n.Normalize("as15169")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != model.QueryASN || got.Query != "AS15169" || got.ASN != 15169 {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestNormalizeRemovesSpaces(t *testing.T) {
	n := New()
	got, err := n.Normalize("  ex ample . com  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.Query != "example.com" {
		t.Fatalf("query: got %q want example.com", got.Query)
	}
}

func TestNormalizeDomainSeparatorTypos(t *testing.T) {
	n := New()
	cases := map[string]string{
		"example,com":                  "example.com",
		"example，com":                  "example.com",
		"example。com":                  "example.com",
		"example．com":                  "example.com",
		"www，example。com":              "www.example.com",
		"https://www，example。com/path": "www.example.com",
	}
	for input, want := range cases {
		got, err := n.Normalize(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if got.Query != want {
			t.Fatalf("%s: got %q want %q", input, got.Query, want)
		}
	}
}

func TestCleanUserInput(t *testing.T) {
	got := CleanUserInput(" whois，example。com ")
	if got != "whois.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizePublicSuffixSecondLevelDomains(t *testing.T) {
	n := New()
	cases := map[string]struct {
		registeredDomain string
		suffix           string
	}{
		"xxx.pp.ua":   {registeredDomain: "xxx.pp.ua", suffix: "pp.ua"},
		"xxx.eu.org":  {registeredDomain: "xxx.eu.org", suffix: "eu.org"},
		"xxx.qzz.io":  {registeredDomain: "xxx.qzz.io", suffix: "qzz.io"},
		"xxx.edu.kg":  {registeredDomain: "xxx.edu.kg", suffix: "edu.kg"},
		"xxx.de5.net": {registeredDomain: "xxx.de5.net", suffix: "de5.net"},
		"xxx.cc.cd":   {registeredDomain: "xxx.cc.cd", suffix: "cc.cd"},
		"xxx.us.ci":   {registeredDomain: "xxx.us.ci", suffix: "us.ci"},
	}
	for input, want := range cases {
		got, err := n.Normalize(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if got.RegisteredDomain != want.registeredDomain || got.Suffix != want.suffix {
			t.Fatalf("%s: registered=%q suffix=%q, want registered=%q suffix=%q", input, got.RegisteredDomain, got.Suffix, want.registeredDomain, want.suffix)
		}
	}
}

func TestNormalizeExactDomainKeepsFullDomain(t *testing.T) {
	n := New()
	got, err := n.NormalizeWithOptions("deep.preview.example.com", model.LookupOptions{ExactDomain: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Query != "deep.preview.example.com" {
		t.Fatalf("query: got %q", got.Query)
	}
	if got.RegisteredDomain != "deep.preview.example.com" {
		t.Fatalf("registered domain: got %q want full domain", got.RegisteredDomain)
	}
	if got.Suffix != "com" {
		t.Fatalf("suffix: got %q want com", got.Suffix)
	}
}

func TestNormalizeDomainInputError(t *testing.T) {
	n := New()
	_, err := n.Normalize("example_com")
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(InputError); !ok {
		t.Fatalf("error type: got %T want InputError", err)
	}
}
