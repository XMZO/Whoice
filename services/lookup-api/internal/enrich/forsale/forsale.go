// Package forsale marks domains listed for sale on a domain marketplace.
//
// Marketplaces serve their for-sale landing pages from dedicated nameservers;
// a domain delegated only to one marketplace's lander nameservers shows that
// page, so its owner has it listed there. General DNS hosting of the same
// companies, ad-parking nameservers (ns1.sedoparking.com, ns1.smartname.com)
// and mixed delegations are deliberately not matched: parking is not a
// listing, and a mix says nothing certain.
package forsale

import (
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type market struct {
	name    string
	website string
	hosts   []string
}

// markets lists only nameservers documented (or long observed) as serving
// for-sale landers and nothing else.
var markets = []market{
	// GoDaddy: Afternic nameservers are only for domains listed through Afternic.
	{name: "Afternic", website: "https://www.afternic.com", hosts: []string{"ns1.afternic.com", "ns2.afternic.com"}},
	// Uniregistry Market landers, now part of Afternic.
	{name: "Afternic", website: "https://www.afternic.com", hosts: []string{"ns1.uniregistrymarket.link", "ns2.uniregistrymarket.link"}},
	{name: "Dan", website: "https://dan.com", hosts: []string{"ns1.dan.com", "ns2.dan.com"}},
	// Undeveloped landers, now served by Dan.
	{name: "Dan", website: "https://dan.com", hosts: []string{"ns1.undeveloped.com", "ns2.undeveloped.com"}},
	{name: "Atom", website: "https://www.atom.com", hosts: []string{"ns1.atom.com", "ns2.atom.com"}},
	// Squadhelp, renamed Atom.
	{name: "Atom", website: "https://www.atom.com", hosts: []string{"ns1.squadhelp.com", "ns2.squadhelp.com"}},
	// Sedo's ad-free sales lander (not ns*.sedoparking.com, which parks with ads).
	{name: "Sedo", website: "https://sedo.com", hosts: []string{"sl1.sedo.com", "sl2.sedo.com"}},
	{name: "Efty", website: "https://efty.com", hosts: []string{"ns1.eftydns.com", "ns2.eftydns.com"}},
	{name: "HugeDomains", website: "https://www.hugedomains.com", hosts: []string{"forsale.hugedomainsdns.com", "domain-for-sale.hugedomainsdns.com"}},
}

// Detect returns the marketplace when every nameserver belongs to one
// marketplace's for-sale landers.
func Detect(nameservers []model.Nameserver) (string, string, bool) {
	if len(nameservers) == 0 {
		return "", "", false
	}
	var found *market
	for _, ns := range nameservers {
		host := strings.ToLower(strings.Trim(strings.TrimSpace(ns.Host), "."))
		m := marketOf(host)
		if m == nil || (found != nil && m.name != found.name) {
			return "", "", false
		}
		found = m
	}
	return found.name, found.website, true
}

func marketOf(host string) *market {
	for i := range markets {
		for _, candidate := range markets[i].hosts {
			if host == candidate {
				return &markets[i]
			}
		}
	}
	return nil
}

// Apply marks a registered domain that is listed for sale.
func Apply(result *model.LookupResult) {
	if result == nil || result.Type != model.QueryDomain || result.Status != model.StatusRegistered {
		return
	}
	if name, website, ok := Detect(result.Nameservers); ok {
		result.Enrichment.ForSale = &model.ForSaleInfo{Market: name, Website: website}
	}
}
