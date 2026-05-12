package dns

import (
	"context"
	"net"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type fakeResolver struct{}

func (fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}}, nil
}

func (fakeResolver) LookupCNAME(context.Context, string) (string, error) {
	return "example.com.", nil
}

func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil
}

func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns1.example.com."}}, nil
}

func TestApplyWithResolver(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	ApplyWithResolver(context.Background(), result, 0, fakeResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if len(result.Enrichment.DNS.A) != 1 || result.Enrichment.DNS.A[0].Version != "ipv4" {
		t.Fatalf("unexpected A records: %+v", result.Enrichment.DNS.A)
	}
	if len(result.Enrichment.DNS.AAAA) != 1 || result.Enrichment.DNS.AAAA[0].Version != "ipv6" {
		t.Fatalf("unexpected AAAA records: %+v", result.Enrichment.DNS.AAAA)
	}
	if result.Enrichment.DNS.CNAME != "example.com" {
		t.Fatalf("unexpected cname %q", result.Enrichment.DNS.CNAME)
	}
	if len(result.Enrichment.DNS.MX) != 1 || result.Enrichment.DNS.MX[0].Host != "mail.example.com" {
		t.Fatalf("unexpected mx: %+v", result.Enrichment.DNS.MX)
	}
	if len(result.Enrichment.DNS.NS) != 1 || result.Enrichment.DNS.NS[0] != "ns1.example.com" {
		t.Fatalf("unexpected ns: %+v", result.Enrichment.DNS.NS)
	}
}
