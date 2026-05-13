package rdapbootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestMatchDNSLongestSuffix(t *testing.T) {
	file := bootstrapFile{Services: [][][]string{
		{{"com"}, {"https://rdap.example/com/"}},
		{{"example.com"}, {"https://rdap.example/private/"}},
	}}
	base, ok, err := matchDNS(file, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || base != "https://rdap.example/private/" {
		t.Fatalf("unexpected match: %q %v", base, ok)
	}
}

func TestMatchIPMostSpecific(t *testing.T) {
	file := bootstrapFile{Services: [][][]string{
		{{"8.0.0.0/8"}, {"https://rdap.example/wide/"}},
		{{"8.8.8.0/24"}, {"https://rdap.example/specific/"}},
	}}
	base, ok, err := matchIP(file, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || base != "https://rdap.example/specific/" {
		t.Fatalf("unexpected match: %q %v", base, ok)
	}
}

func TestMatchASNRange(t *testing.T) {
	file := bootstrapFile{Services: [][][]string{
		{{"1-1876"}, {"https://rdap.example/asn/"}},
	}}
	base, ok, err := matchASN(file, 151)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || base != "https://rdap.example/asn/" {
		t.Fatalf("unexpected match: %q %v", base, ok)
	}
}

func TestBootstrapKindForCIDR(t *testing.T) {
	kind, key, err := bootstrapKindAndKey(model.NormalizedQuery{Type: model.QueryCIDR, Query: "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if kind != "ipv6" || key != "2001:db8::" {
		t.Fatalf("unexpected kind/key: %s %s", kind, key)
	}
}

func TestSnapshotResolverCoversCommonQueries(t *testing.T) {
	resolver, err := NewSnapshotResolver()
	if err != nil {
		t.Fatal(err)
	}

	tests := []model.NormalizedQuery{
		{Type: model.QueryDomain, Query: "example.com"},
		{Type: model.QueryIPv4, Query: "8.8.8.8"},
		{Type: model.QueryASN, Query: "AS15169", ASN: 15169},
		{Type: model.QueryIPv6, Query: "2606:4700:4700::1111"},
	}
	for _, tt := range tests {
		base, ok, err := resolver.BaseURL(t.Context(), tt)
		if err != nil {
			t.Fatalf("%s: %v", tt.Query, err)
		}
		if !ok || base == "" {
			t.Fatalf("%s: expected snapshot match, got %q %v", tt.Query, base, ok)
		}
	}
}

func TestSnapshotResolverUsesExtraRDAPOverlay(t *testing.T) {
	resolver, err := NewSnapshotResolver()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"example.li":     "https://rdap.nic.li/",
		"example.ch":     "https://rdap.nic.ch/",
		"example.eu.com": "https://rdap.centralnic.com/eu.com/",
	}
	for query, want := range tests {
		base, ok, err := resolver.BaseURL(context.Background(), model.NormalizedQuery{Type: model.QueryDomain, Query: query})
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if !ok || base != want {
			t.Fatalf("%s: got %q %v want %q", query, base, ok, want)
		}
	}
}

type resolverFunc func(model.NormalizedQuery) (string, bool, error)

func (f resolverFunc) BaseURL(_ context.Context, q model.NormalizedQuery) (string, bool, error) {
	return f(q)
}

func TestFallbackResolverUsesFallbackWhenPrimaryMissesOrErrors(t *testing.T) {
	q := model.NormalizedQuery{Type: model.QueryDomain, Query: "example.test"}
	fallback := resolverFunc(func(model.NormalizedQuery) (string, bool, error) {
		return "https://rdap.example/", true, nil
	})

	tests := []Resolver{
		resolverFunc(func(model.NormalizedQuery) (string, bool, error) { return "", false, nil }),
		resolverFunc(func(model.NormalizedQuery) (string, bool, error) { return "", false, errors.New("boom") }),
	}
	for _, primary := range tests {
		resolver := FallbackResolver{Primary: primary, Fallback: fallback}
		base, ok, err := resolver.BaseURL(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if !ok || base != "https://rdap.example/" {
			t.Fatalf("unexpected fallback result %q %v", base, ok)
		}
	}
}

func TestFileResolverReadsMountedDataDir(t *testing.T) {
	dir := t.TempDir()
	rdapDir := filepath.Join(dir, "rdap-bootstrap")
	if err := os.MkdirAll(rdapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"services":[[["test"],["https://rdap.mounted.example/"]]]}`
	if err := os.WriteFile(filepath.Join(rdapDir, "dns.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	resolver, err := NewFileResolver(dir)
	if err != nil {
		t.Fatal(err)
	}
	base, ok, err := resolver.BaseURL(context.Background(), model.NormalizedQuery{Type: model.QueryDomain, Query: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || base != "https://rdap.mounted.example/" {
		t.Fatalf("unexpected mounted data result %q %v", base, ok)
	}
}

func TestFileResolverAppliesExtraRDAPOverlay(t *testing.T) {
	dir := t.TempDir()
	rdapDir := filepath.Join(dir, "rdap-bootstrap")
	if err := os.MkdirAll(rdapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"services":[[["com"],["https://rdap.example/com/"]]]}`
	if err := os.WriteFile(filepath.Join(rdapDir, "dns.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := `{"li":"https://rdap.nic.li/","eu.com":"https://rdap.centralnic.com/eu.com/"}`
	if err := os.WriteFile(filepath.Join(rdapDir, "extra.json"), []byte(extra), 0o644); err != nil {
		t.Fatal(err)
	}

	resolver, err := NewFileResolver(dir)
	if err != nil {
		t.Fatal(err)
	}
	base, ok, err := resolver.BaseURL(context.Background(), model.NormalizedQuery{Type: model.QueryDomain, Query: "example.li"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || base != "https://rdap.nic.li/" {
		t.Fatalf("unexpected extra RDAP result %q %v", base, ok)
	}
	base, ok, err = resolver.BaseURL(context.Background(), model.NormalizedQuery{Type: model.QueryDomain, Query: "www.example.eu.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || base != "https://rdap.centralnic.com/eu.com/" {
		t.Fatalf("unexpected second-level RDAP result %q %v", base, ok)
	}
}
