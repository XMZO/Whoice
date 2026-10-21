package forsale

import (
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func ns(hosts ...string) []model.Nameserver {
	out := make([]model.Nameserver, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, model.Nameserver{Host: host})
	}
	return out
}

func TestDetectRequiresEveryNameserverOnOneMarketplace(t *testing.T) {
	for _, tc := range []struct {
		hosts []string
		want  string
	}{
		{[]string{"ns1.atom.com", "NS2.ATOM.COM."}, "Atom"},
		{[]string{"ns1.afternic.com", "ns2.afternic.com"}, "Afternic"},
		{[]string{"ns1.afternic.com", "ns2.uniregistrymarket.link"}, "Afternic"},
		{[]string{"sl1.sedo.com", "sl2.sedo.com"}, "Sedo"},
		{[]string{"forsale.hugedomainsdns.com", "domain-for-sale.hugedomainsdns.com"}, "HugeDomains"},
	} {
		if got, _, ok := Detect(ns(tc.hosts...)); !ok || got != tc.want {
			t.Fatalf("Detect(%v) = %q, %v; want %q", tc.hosts, got, ok, tc.want)
		}
	}
	for _, hosts := range [][]string{
		nil,
		{"ns1.sedoparking.com", "ns2.sedoparking.com"}, // ad parking, not a listing
		{"ns1.atom.com", "ns1.cloudflare.com"},         // mixed delegation
		{"ns1.atom.com", "ns1.dan.com"},                // two marketplaces
		{"ns1.atom.com.example.net"},
		{"launch1.spaceship.net", "launch2.spaceship.net"},
	} {
		if got, _, ok := Detect(ns(hosts...)); ok {
			t.Fatalf("Detect(%v) = %q; want no match", hosts, got)
		}
	}
}

func TestApplyOnlyMarksRegisteredDomains(t *testing.T) {
	result := &model.LookupResult{Type: model.QueryDomain, Status: model.StatusReserved, Nameservers: ns("ns1.atom.com", "ns2.atom.com")}
	Apply(result)
	if result.Enrichment.ForSale != nil {
		t.Fatal("a reserved domain must not be marked for sale")
	}
	result.Status = model.StatusRegistered
	Apply(result)
	if result.Enrichment.ForSale == nil || result.Enrichment.ForSale.Market != "Atom" {
		t.Fatalf("expected Atom, got %+v", result.Enrichment.ForSale)
	}
}
