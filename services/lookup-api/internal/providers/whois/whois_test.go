package whois

import (
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
	ianaAL := "% IANA WHOIS server\nrefer:        \n\ndomain:       AL\n\norganisation: Electronic and Postal Communications Authority - AKEP\n"
	if !isBareIANATLDRecord(domain, []string{"whois.iana.org"}, ianaAL) {
		t.Fatal("IANA TLD record without referral should be rejected for a domain query")
	}
	if tldOf(domain) != "al" {
		t.Fatalf("tld: %q", tldOf(domain))
	}
	withReferral := "% IANA WHOIS server\nrefer:        whois.nic.example\n\ndomain:       EXAMPLE\n"
	if isBareIANATLDRecord(domain, []string{"whois.iana.org"}, withReferral) {
		t.Fatal("a referral means the registry has a WHOIS server")
	}
	if isBareIANATLDRecord(domain, []string{"whois.iana.org", "whois.nic.example"}, ianaAL) {
		t.Fatal("followed referrals are registry data")
	}
	asn := model.NormalizedQuery{Type: model.QueryASN, Query: "AS13335"}
	if isBareIANATLDRecord(asn, []string{"whois.iana.org"}, "as-block: AS13312-AS18431\n") {
		t.Fatal("non-domain IANA answers are kept")
	}
}
