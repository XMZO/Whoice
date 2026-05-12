package parsers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type parserExpected struct {
	Status            model.ResultStatus `json:"status"`
	DomainName        string             `json:"domainName"`
	RegistrarName     string             `json:"registrarName"`
	RegistrarIanaID   string             `json:"registrarIanaId"`
	CreatedAt         string             `json:"createdAt"`
	ExpiresAt         string             `json:"expiresAt"`
	UpdatedAt         string             `json:"updatedAt"`
	Statuses          []string           `json:"statuses"`
	Nameservers       []string           `json:"nameservers"`
	DNSSEC            string             `json:"dnssec"`
	RegistrantCountry string             `json:"registrantCountry"`
}

func TestWHOISParserFixtures(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		expect string
		query  model.NormalizedQuery
	}{
		{
			name:   "registered",
			raw:    fixturePath("whois", "generic", "registered.raw"),
			expect: fixturePath("whois", "generic", "registered.expected.json"),
			query:  domainQuery("example.com"),
		},
		{
			name:   "unregistered",
			raw:    fixturePath("whois", "generic", "unregistered.raw"),
			expect: fixturePath("whois", "generic", "unregistered.expected.json"),
			query:  domainQuery("example-missing.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawBody := readString(t, tt.raw)
			expected := readExpected(t, tt.expect)
			part, err := WHOISParser{}.Parse(context.Background(), model.RawResponse{
				Source: model.SourceWHOIS,
				Query:  tt.query.Query,
				Body:   rawBody,
			}, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			assertPartial(t, part, expected)
		})
	}
}

func TestTLDWHOISParserFixtures(t *testing.T) {
	registry := NewRegistry(WHOISParser{}, UKWHOISParser{}, JPWHOISParser{}, FRWHOISParser{}, CNWHOISParser{}, BRWHOISParser{}, ITWHOISParser{}, EUWHOISParser{}, BEWHOISParser{}, PLWHOISParser{}, CZWHOISParser{}, HUWHOISParser{}, SKWHOISParser{}, ROWHOISParser{})
	tests := []struct {
		name   string
		raw    string
		expect string
		query  model.NormalizedQuery
	}{
		{
			name:   "uk",
			raw:    fixturePath("whois", "uk", "registered.raw"),
			expect: fixturePath("whois", "uk", "registered.expected.json"),
			query:  domainQueryFor("example.uk", "uk"),
		},
		{
			name:   "jp",
			raw:    fixturePath("whois", "jp", "registered.raw"),
			expect: fixturePath("whois", "jp", "registered.expected.json"),
			query:  domainQueryFor("example.jp", "jp"),
		},
		{
			name:   "fr",
			raw:    fixturePath("whois", "fr", "registered.raw"),
			expect: fixturePath("whois", "fr", "registered.expected.json"),
			query:  domainQueryFor("example.fr", "fr"),
		},
		{
			name:   "cn",
			raw:    fixturePath("whois", "cn", "registered.raw"),
			expect: fixturePath("whois", "cn", "registered.expected.json"),
			query:  domainQueryFor("example.cn", "cn"),
		},
		{
			name:   "br",
			raw:    fixturePath("whois", "br", "registered.raw"),
			expect: fixturePath("whois", "br", "registered.expected.json"),
			query:  domainQueryFor("example.br", "br"),
		},
		{
			name:   "it",
			raw:    fixturePath("whois", "it", "registered.raw"),
			expect: fixturePath("whois", "it", "registered.expected.json"),
			query:  domainQueryFor("example.it", "it"),
		},
		{
			name:   "eu",
			raw:    fixturePath("whois", "eu", "registered.raw"),
			expect: fixturePath("whois", "eu", "registered.expected.json"),
			query:  domainQueryFor("example.eu", "eu"),
		},
		{
			name:   "be",
			raw:    fixturePath("whois", "be", "registered.raw"),
			expect: fixturePath("whois", "be", "registered.expected.json"),
			query:  domainQueryFor("example.be", "be"),
		},
		{
			name:   "pl",
			raw:    fixturePath("whois", "pl", "registered.raw"),
			expect: fixturePath("whois", "pl", "registered.expected.json"),
			query:  domainQueryFor("example.pl", "pl"),
		},
		{
			name:   "cz",
			raw:    fixturePath("whois", "cz", "registered.raw"),
			expect: fixturePath("whois", "cz", "registered.expected.json"),
			query:  domainQueryFor("example.cz", "cz"),
		},
		{
			name:   "hu",
			raw:    fixturePath("whois", "hu", "registered.raw"),
			expect: fixturePath("whois", "hu", "registered.expected.json"),
			query:  domainQueryFor("example.hu", "hu"),
		},
		{
			name:   "sk",
			raw:    fixturePath("whois", "sk", "registered.raw"),
			expect: fixturePath("whois", "sk", "registered.expected.json"),
			query:  domainQueryFor("example.sk", "sk"),
		},
		{
			name:   "ro",
			raw:    fixturePath("whois", "ro", "registered.raw"),
			expect: fixturePath("whois", "ro", "registered.expected.json"),
			query:  domainQueryFor("example.ro", "ro"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawBody := readString(t, tt.raw)
			expected := readExpected(t, tt.expect)
			part, err := registry.Parse(context.Background(), model.RawResponse{
				Source: model.SourceWHOIS,
				Query:  tt.query.Query,
				Body:   rawBody,
			}, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			assertPartial(t, part, expected)
		})
	}
}

func TestWHOISWebNoticeIsUnknown(t *testing.T) {
	q := domainQueryFor("example.ao", "ao")
	part, err := WHOISParser{}.Parse(context.Background(), model.RawResponse{
		Source: model.SourceWHOISWeb,
		Query:  q.Query,
		Body:   "WHOIS Web fallback notice: Please visit https://www.dns.ao/ao/whois/ for example.ao.",
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if part.Status != model.StatusUnknown {
		t.Fatalf("status: got %q want %q", part.Status, model.StatusUnknown)
	}
	if part.Raw.WHOISWeb == "" {
		t.Fatal("expected raw WHOIS Web payload")
	}
}

func TestRDAPParserFixtures(t *testing.T) {
	rawBody := readString(t, fixturePath("rdap", "domain", "registered.json"))
	expected := readExpected(t, fixturePath("rdap", "domain", "registered.expected.json"))
	q := domainQuery("example.com")
	part, err := RDAPParser{}.Parse(context.Background(), model.RawResponse{
		Source:     model.SourceRDAP,
		Query:      q.Query,
		Body:       rawBody,
		StatusCode: 200,
		Server:     "https://rdap.example/domain/example.com",
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	assertPartial(t, part, expected)
}

func assertPartial(t *testing.T, part *model.PartialResult, expected parserExpected) {
	t.Helper()
	if part.Status != expected.Status {
		t.Fatalf("status: got %q want %q", part.Status, expected.Status)
	}
	if expected.DomainName != "" && part.Domain.Name != expected.DomainName {
		t.Fatalf("domain: got %q want %q", part.Domain.Name, expected.DomainName)
	}
	if expected.RegistrarName != "" && part.Registrar.Name != expected.RegistrarName {
		t.Fatalf("registrar: got %q want %q", part.Registrar.Name, expected.RegistrarName)
	}
	if expected.RegistrarIanaID != "" && part.Registrar.IANAID != expected.RegistrarIanaID {
		t.Fatalf("iana id: got %q want %q", part.Registrar.IANAID, expected.RegistrarIanaID)
	}
	if expected.CreatedAt != "" && part.Dates.CreatedAt != expected.CreatedAt {
		t.Fatalf("created: got %q want %q", part.Dates.CreatedAt, expected.CreatedAt)
	}
	if expected.ExpiresAt != "" && part.Dates.ExpiresAt != expected.ExpiresAt {
		t.Fatalf("expires: got %q want %q", part.Dates.ExpiresAt, expected.ExpiresAt)
	}
	if expected.UpdatedAt != "" && part.Dates.UpdatedAt != expected.UpdatedAt {
		t.Fatalf("updated: got %q want %q", part.Dates.UpdatedAt, expected.UpdatedAt)
	}
	if expected.DNSSEC != "" && part.DNSSEC.Text != expected.DNSSEC {
		t.Fatalf("dnssec: got %q want %q", part.DNSSEC.Text, expected.DNSSEC)
	}
	if expected.RegistrantCountry != "" && part.Registrant.Country != expected.RegistrantCountry {
		t.Fatalf("registrant country: got %q want %q", part.Registrant.Country, expected.RegistrantCountry)
	}
	assertStatuses(t, part.Statuses, expected.Statuses)
	assertNameservers(t, part.Nameservers, expected.Nameservers)
}

func assertStatuses(t *testing.T, got []model.DomainStatus, expected []string) {
	t.Helper()
	if len(got) != len(expected) {
		t.Fatalf("statuses: got %d want %d", len(got), len(expected))
	}
	for i, value := range expected {
		if got[i].Code != value {
			t.Fatalf("status[%d]: got %q want %q", i, got[i].Code, value)
		}
	}
}

func assertNameservers(t *testing.T, got []model.Nameserver, expected []string) {
	t.Helper()
	if len(got) != len(expected) {
		t.Fatalf("nameservers: got %d want %d", len(got), len(expected))
	}
	for i, value := range expected {
		if got[i].Host != value {
			t.Fatalf("nameserver[%d]: got %q want %q", i, got[i].Host, value)
		}
	}
}

func readExpected(t *testing.T, path string) parserExpected {
	t.Helper()
	var expected parserExpected
	if err := json.Unmarshal([]byte(readString(t, path)), &expected); err != nil {
		t.Fatal(err)
	}
	return expected
}

func readString(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func fixturePath(parts ...string) string {
	all := append([]string{"..", "..", "..", "..", "packages", "fixtures"}, parts...)
	return filepath.Join(all...)
}

func domainQuery(value string) model.NormalizedQuery {
	return domainQueryFor(value, "com")
}

func domainQueryFor(value, suffix string) model.NormalizedQuery {
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
