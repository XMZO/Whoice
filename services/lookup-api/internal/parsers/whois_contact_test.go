package parsers

import (
	"context"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestWHOISRegistrantEmailDropsRedactionSentence(t *testing.T) {
	raw := model.RawResponse{Source: model.SourceWHOIS, Server: "whois.nic.cat", Body: "Domain Name: kotori.cat\n" +
		"Registrant Country: CN\n" +
		"Registrant Email: Please query the Whois service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.\n"}
	part, err := (WHOISParser{}).Parse(context.Background(), raw, model.NormalizedQuery{Type: model.QueryDomain, Query: "kotori.cat"})
	if err != nil {
		t.Fatal(err)
	}
	if part.Registrant.Email != "" || part.Registrant.Country != "CN" {
		t.Fatalf("registrant: %#v", part.Registrant)
	}
	for _, keep := range []string{"owner@example.cat", "https://whois.example/contact/kotori.cat"} {
		if got := contactEmail(keep); got != keep {
			t.Fatalf("contactEmail(%q) = %q", keep, got)
		}
	}
}

func TestContactPhoneDropsPlaceholders(t *testing.T) {
	for value, want := range map[string]string{"+000000000": "", "+0.0000000000": "", "+216.71840721": "+216.71840721", "": ""} {
		if got := contactPhone(value); got != want {
			t.Fatalf("contactPhone(%q) = %q, want %q", value, got, want)
		}
	}
}
