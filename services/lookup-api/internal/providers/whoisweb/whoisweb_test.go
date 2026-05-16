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

func TestDZModuleBuildsWHOISBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains/example.dz" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"domainName":   "example.dz",
			"registrar":    "Example Registrar DZ",
			"creationDate": "2000-01-10",
			"orgName":      "Example Organization",
			"contactAdm":   "Example Admin",
			"emailAdm":     "admin@example.dz",
		})
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), DZModule{BaseURL: server.URL})
	raw, err := provider.Lookup(context.Background(), domainQuery("example.dz", "dz"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"Domain Name: example.dz",
		"Registrar: Example Registrar DZ",
		"Creation Date: 2000-01-10",
		"Registrant Organization: Example Organization",
		"Admin Email: admin@example.dz",
	} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, raw.Body)
		}
	}
}

func TestNIModuleBuildsWHOISBodyAnd404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dominio") == "missing.ni" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/dominios/whois" || r.URL.Query().Get("dominio") != "example.ni" {
			t.Fatalf("unexpected request %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"datos": map[string]any{
				"fechaExpiracion": "2027-01-10",
				"cliente":         "Example Registrant",
				"direccion":       "Example Address",
			},
			"contactos": map[string]any{
				"tipoContacto": "admin",
				"nombre":       "Example Contact",
				"correoElectronico": []map[string]string{
					{"value": "admin@example.ni"},
				},
				"telefono": "50500000000",
			},
		})
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), NIModule{BaseURL: server.URL})
	raw, err := provider.Lookup(context.Background(), domainQuery("example.ni", "ni"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Domain Name: example.ni",
		"Registry Expiry Date: 2027-01-10",
		"Registrant Name: Example Registrant",
		"Contact Email: admin@example.ni",
	} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, raw.Body)
		}
	}

	missing, err := provider.Lookup(context.Background(), domainQuery("missing.ni", "ni"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(missing.Body, "Domain not found") {
		t.Fatalf("expected not found body, got %q", missing.Body)
	}
}

func TestLKModuleBuildsWHOISBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/domains/single-search" || r.URL.Query().Get("keyword") != "example.lk" {
			t.Fatalf("unexpected request %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"domainAvailability": map[string]any{
					"message":    "Domain name is already registered",
					"domainName": "example.lk",
					"domainInfo": map[string]any{
						"expireDate":   "Friday, 31st March, 2027",
						"registeredTo": "Example Registrant",
					},
				},
			},
		})
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), LKModule{BaseURL: server.URL})
	raw, err := provider.Lookup(context.Background(), domainQuery("example.lk", "lk"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Message: Domain name is already registered",
		"Domain Name: example.lk",
		"Registry Expiry Date: 2027-03-31",
		"Registrant Name: Example Registrant",
	} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, raw.Body)
		}
	}
}

func TestMTModuleExtractsPreWHOIS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dotmt/whois/" || r.URL.RawQuery != "example.mt" {
			t.Fatalf("unexpected request %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><pre>Domain Name: example.mt
Registrar: Example MT
Name Server: ns1.example.mt
</pre></body></html>`))
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), MTModule{BaseURL: server.URL})
	raw, err := provider.Lookup(context.Background(), domainQuery("example.mt", "mt"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Domain Name: example.mt",
		"Registrar: Example MT",
		"Name Server: ns1.example.mt",
	} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, raw.Body)
		}
	}
}

func TestPAModuleBuildsWHOISBodyAnd404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/whois/missing.pa" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/whois/example.pa" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"payload": map[string]any{
				"Dominio":             "example.pa",
				"fecha_actualizacion": "2026-02-03",
				"fecha_creacion":      "2020-02-03",
				"fecha_expiracion":    "2027-02-03",
				"Estatus":             "clientTransferProhibited",
				"NS":                  []string{"ns1.example.pa", "ns2.example.pa"},
				"titular": map[string]any{
					"contacto": map[string]any{
						"nombre":     "Example Holder",
						"direccion1": "Street 1",
						"direccion2": "Suite 2",
						"ciudad":     "Panama",
						"estado":     "Panama",
						"ubicacion":  "PA",
						"telefono":   "+507000000",
						"email":      "holder@example.pa",
					},
				},
			},
		})
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), PAModule{BaseURL: server.URL})
	raw, err := provider.Lookup(context.Background(), domainQuery("example.pa", "pa"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Domain Name: example.pa",
		"Updated Date: 2026-02-03",
		"Creation Date: 2020-02-03",
		"Registry Expiry Date: 2027-02-03",
		"Domain Status: clientTransferProhibited",
		"Name Server: ns1.example.pa",
		"Registrant Name: Example Holder",
		"Registrant Street: Street 1, Suite 2",
		"Registrant Email: holder@example.pa",
	} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, raw.Body)
		}
	}

	missing, err := provider.Lookup(context.Background(), domainQuery("missing.pa", "pa"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(missing.Body, "Domain not found") {
		t.Fatalf("expected not found body, got %q", missing.Body)
	}
}

func TestDefaultModulesCoverPhase3WebFallbacks(t *testing.T) {
	provider := NewWithClient(nil, DefaultModules()...)
	for _, suffix := range []string{"ao", "az", "ba", "cy", "dj", "dz", "gq", "lk", "mt", "ni", "pa", "py", "vn"} {
		if !provider.Supports(domainQuery("example."+suffix, suffix)) {
			t.Fatalf("expected WHOIS Web module for .%s", suffix)
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
