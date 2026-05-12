package whoisservers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestResolveCommonTLD(t *testing.T) {
	server, query, err := NewResolver().Resolve(model.NormalizedQuery{
		Type:   model.QueryDomain,
		Query:  "example.com",
		Suffix: "com",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if server.Host != "whois.verisign-grs.com" {
		t.Fatalf("unexpected server %q", server.Host)
	}
	if query != "=example.com" {
		t.Fatalf("unexpected query %q", query)
	}
}

func TestResolveUsesEmbeddedSnapshot(t *testing.T) {
	server, _, err := NewResolver().Resolve(model.NormalizedQuery{
		Type:   model.QueryDomain,
		Query:  "example.ac",
		Suffix: "ac",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if server.Host != "whois.nic.ac" {
		t.Fatalf("unexpected embedded snapshot server %q", server.Host)
	}
}

func TestResolveUsesExtraSecondLevelServer(t *testing.T) {
	server, _, err := NewResolver().Resolve(model.NormalizedQuery{
		Type:             model.QueryDomain,
		Query:            "example.uk.com",
		Suffix:           "com",
		RegisteredDomain: "example.uk.com",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if server.Host != "whois.centralnic.com" {
		t.Fatalf("unexpected extra server %q", server.Host)
	}
}

func TestResolveUsesPublicSuffixSecondLevelServers(t *testing.T) {
	tests := map[string]string{
		"xxx.pp.ua":   "whois.pp.ua",
		"xxx.eu.org":  "whois.eu.org",
		"xxx.qzz.io":  "whois.digitalplat.org",
		"xxx.de5.net": "whois.dnshe.com",
		"xxx.cc.cd":   "whois.dnshe.com",
		"xxx.us.ci":   "whois.dnshe.com",
	}
	for query, wantHost := range tests {
		server, _, err := NewResolver().Resolve(model.NormalizedQuery{
			Type:             model.QueryDomain,
			Query:            query,
			Suffix:           suffixAfterFirstLabel(query),
			RegisteredDomain: query,
		}, "")
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if server.Host != wantHost {
			t.Fatalf("%s: got %q want %q", query, server.Host, wantHost)
		}
	}
}

func suffixAfterFirstLabel(query string) string {
	for index, char := range query {
		if char == '.' {
			return query[index+1:]
		}
	}
	return query
}

func TestResolveUsesRegistryServerForOfficialSecondLevelSuffix(t *testing.T) {
	server, _, err := NewResolver().Resolve(model.NormalizedQuery{
		Type:             model.QueryDomain,
		Query:            "xxx.edu.kg",
		Suffix:           "edu.kg",
		RegisteredDomain: "xxx.edu.kg",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if server.Host != "whois.kg" {
		t.Fatalf("unexpected server %q", server.Host)
	}
}

func TestResolveUsesMountedServerData(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "whois-servers")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"example":{"host":"whois.mounted.example","query":"domain %s\r\n"}}`)
	if err := os.WriteFile(filepath.Join(dataDir, "extra.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	server, query, err := NewResolver(dir).Resolve(model.NormalizedQuery{
		Type:   model.QueryDomain,
		Query:  "demo.example",
		Suffix: "example",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if server.Host != "whois.mounted.example" || query != "domain demo.example" {
		t.Fatalf("mounted server: %#v query=%q", server, query)
	}
}

func TestResolveFallback(t *testing.T) {
	server, query, err := NewResolver().Resolve(model.NormalizedQuery{
		Type:   model.QueryDomain,
		Query:  "example.unknown",
		Suffix: "unknown",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if server.Host != "whois.iana.org" || query != "example.unknown" {
		t.Fatalf("unexpected fallback %q %q", server.Host, query)
	}
}

func TestResolveExpandedCCTLDs(t *testing.T) {
	tests := map[string]string{
		"jp": "whois.jprs.jp",
		"uk": "whois.nic.uk",
		"eu": "whois.eu",
		"pl": "whois.dns.pl",
		"se": "whois.iis.se",
	}
	for suffix, wantHost := range tests {
		server, _, err := NewResolver().Resolve(model.NormalizedQuery{
			Type:   model.QueryDomain,
			Query:  "example." + suffix,
			Suffix: suffix,
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		if server.Host != wantHost {
			t.Fatalf("%s: got %q want %q", suffix, server.Host, wantHost)
		}
	}
}
