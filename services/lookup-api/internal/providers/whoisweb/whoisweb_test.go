package whoisweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestNoticeModule(t *testing.T) {
	provider := NewWithClient(nil, NewNoticeModule(map[string]string{
		"ao": "https://www.dns.ao/ao/whois/",
	}))
	q := domainQuery("example.ao", "ao")

	raw, err := provider.Lookup(context.Background(), q, model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if raw.Source != model.SourceWHOISWeb {
		t.Fatalf("source: got %q", raw.Source)
	}
	if !strings.Contains(raw.Body, "WHOIS Web fallback notice") {
		t.Fatalf("expected notice body, got %q", raw.Body)
	}
}

func TestVNModuleBuildsWHOISBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/whois/domainspecify/example.vn" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":       "0",
			"domainName": "example.vn",
			"registrar":  "Example Registrar",
			"rawtext": `{
				"issuedDate": {"year": 2001, "month": 3, "day": 26, "hour": 0, "minute": 0, "second": 0, "timezone": 0},
				"expiredDate": {"year": 2027, "month": 3, "day": 31, "hour": 0, "minute": 0, "second": 0, "timezone": 0}
			}`,
			"status":     []string{"clientTransferProhibited"},
			"nameServer": []string{"ns1.example.vn", "ns2.example.vn"},
			"DNSSEC":     "unsigned",
		})
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), VNModule{BaseURL: server.URL})
	raw, err := provider.Lookup(context.Background(), domainQuery("example.vn", "vn"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"Domain Name: example.vn",
		"Registrar: Example Registrar",
		"Creation Date: 2001-03-26T00:00:00Z",
		"Registry Expiry Date: 2027-03-31T00:00:00Z",
		"Name Server: ns1.example.vn",
	} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, raw.Body)
		}
	}
}

func domainQuery(value, suffix string) model.NormalizedQuery {
	return model.NormalizedQuery{
		Input:            value,
		Query:            value,
		UnicodeQuery:     value,
		Type:             model.QueryDomain,
		Host:             value,
		Suffix:           suffix,
		RegisteredDomain: value,
	}
}
