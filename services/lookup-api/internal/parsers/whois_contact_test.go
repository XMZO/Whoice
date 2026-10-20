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
