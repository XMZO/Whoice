package whois

import (
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestDecodeWHOISBodyKeepsUTF8(t *testing.T) {
	got := decodeWHOISBody([]byte("registrar: Example\n"))
	if got != "registrar: Example\n" {
		t.Fatalf("decoded: %q", got)
	}
}

func TestDecodeWHOISBodyHandlesWindows1252(t *testing.T) {
	got := decodeWHOISBody([]byte{0x52, 0xe9, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72})
	if got != "Régistrar" {
		t.Fatalf("decoded: %q", got)
	}
}

func TestBareIANATLDRecordIsNotADomainRecord(t *testing.T) {
	domain := model.NormalizedQuery{Type: model.QueryDomain, Query: "google.al"}
	if !isBareIANATLDRecord(domain, []string{"whois.iana.org"}) {
		t.Fatal("IANA TLD record without referral should be rejected for a domain query")
	}
	if tldOf(domain) != "al" {
		t.Fatalf("tld: %q", tldOf(domain))
	}
	// A referral that was not answered leaves only the IANA record too.
	if !isBareIANATLDRecord(domain, []string{"whois.iana.org"}) {
		t.Fatal("an unanswered referral still leaves only TLD data")
	}
	if isBareIANATLDRecord(domain, []string{"whois.iana.org", "whois.nic.example"}) {
		t.Fatal("followed referrals are registry data")
	}
	asn := model.NormalizedQuery{Type: model.QueryASN, Query: "AS13335"}
	if isBareIANATLDRecord(asn, []string{"whois.iana.org"}) {
		t.Fatal("non-domain IANA answers are kept")
	}
}

func TestRefusalNoticesAreNotRecords(t *testing.T) {
	for _, body := range []string{
		"Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries.\n",
		"whois.nic.bo solo acepta consultas con dominios .bo\n",
		"% Query rate limit exceeded. Reduced information.\n",
	} {
		if refusalPattern.FindString(body) == "" {
			t.Fatalf("refusal not recognized: %q", body)
		}
	}
	if refusalPattern.FindString("Domain Name: example.ch\nRegistrar: Example AG\n") != "" {
		t.Fatal("a normal record is not a refusal")
	}
}

func TestRateLimitNoticesAreRefusals(t *testing.T) {
	for _, body := range []string{
		"% Maximum query rate reached\n",
		"Too many connections, try again later\n",
		"% Request limit exceeded\n",
		"Error: ratelimit exceeded\r\n",
	} {
		if refusalPattern.FindString(body) == "" {
			t.Fatalf("not recognized: %q", body)
		}
	}
}

func TestRefusalIgnoresRecordsAndTermsParagraphs(t *testing.T) {
	terms := "Terms of Use: Access to WHOIS information is provided ... " + strings.Repeat("lawful purposes only, ", 60) + "and if you submit too many queries your access may be limited."
	record := "Domain Name: google.mu\nRegistrar URL: http://www.markmonitor.com\nCreation Date: 2000-12-20T13:00:00Z\n" + terms + "\n"
	if got := findRefusal(record); got != "" {
		t.Fatalf("a record with a terms paragraph is not a refusal: %q", got)
	}
	if got := findRefusal(terms + "\n"); got != "" {
		t.Fatalf("a long terms line alone is not a refusal: %q", got)
	}
	if got := findRefusal("Error: ratelimit exceeded\r\n"); got != "Error: ratelimit exceeded" {
		t.Fatalf("short refusals still count: %q", got)
	}
}
