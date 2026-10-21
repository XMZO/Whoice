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

func TestDZModuleBuildsWHOISBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/hal+json")
		if r.URL.Path == "/domains/missing.com.dz" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"title":"Domain Not Found","status":404}`))
			return
		}
		if r.URL.Path != "/domains/example.dz" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		// The live API answers a found domain with 302 and no Location.
		w.WriteHeader(http.StatusFound)
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

	missing, err := provider.Lookup(context.Background(), domainQuery("missing.com.dz", "com.dz"), model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if missing.Body != "Domain Not Found" {
		t.Fatalf("expected not found body, got %q", missing.Body)
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
				// The API now sends one object; older answers used a list.
				"correoElectronico": map[string]string{"value": "admin@example.ni"},
				"telefono":          "50500000000",
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
	for _, suffix := range []string{"ao", "az", "ba", "cy", "dj", "dz", "gq", "lk", "mt", "ni", "pa", "py", "vn", "com.pa", "com.ni", "com.dz", "com.lk", "com.mt"} {
		if !provider.Supports(domainQuery("example."+suffix, suffix)) {
			t.Fatalf("expected WHOIS Web module for .%s", suffix)
		}
	}
}

// Registry lookups run even with the WHOIS Web switch off; notice-only
// suffixes (including .mt and .vn, whose lookups need a CAPTCHA) do not.
func TestRegistryModulesAreRequired(t *testing.T) {
	provider := NewWithClient(nil, DefaultModules()...)
	for _, suffix := range []string{"dz", "lk", "ni", "pa", "com.pa", "com.ni", "us.ci"} {
		if !provider.Required(domainQuery("example."+suffix, suffix)) {
			t.Fatalf("expected .%s to be a required registry lookup", suffix)
		}
	}
	for _, suffix := range []string{"mt", "vn", "ao", "py"} {
		if provider.Required(domainQuery("example."+suffix, suffix)) {
			t.Fatalf("expected .%s to be notice-only", suffix)
		}
	}
	raw, err := provider.Lookup(context.Background(), domainQuery("example.vn", "vn"), model.LookupOptions{})
	if err != nil || !strings.Contains(raw.Body, "vnnic.vn") {
		t.Fatalf("expected a VNNIC notice, got %v %v", raw, err)
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

func TestDNSHEModuleConvertsJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("domain") == "free.cc.cd" {
			_, _ = w.Write([]byte(`{"success":true,"domain":"free.cc.cd","registered":false,"status":"unregistered","registrant_country":"-","name_servers":[],"message":"domain not registered"}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"domain":"anby.cc.cd","registered":true,"status":"active","created_at":"2026-02-14 11:07","expires_at":"2028-02-14 11:07","registrar":"DNSHE","registrar_url":"https://www.dnshe.com","registrant_name":"REDACTED FOR PRIVACY","registrant_email":"abuse@dnshe.com","registrant_country":"REDACTED FOR PRIVACY","name_servers":["renan.ns.cloudflare.com","robin.ns.cloudflare.com"],"dnssec":"Unsigned"}`))
	}))
	defer server.Close()

	provider := NewWithClient(server.Client(), DNSHEModule{BaseURL: server.URL})
	q := model.NormalizedQuery{Type: model.QueryDomain, Query: "anby.cc.cd", Suffix: "cc.cd", RegisteredDomain: "anby.cc.cd"}
	if !provider.Supports(q) || !provider.Required(q) {
		t.Fatal("cc.cd should be supported and required")
	}
	raw, err := provider.Lookup(context.Background(), q, model.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Registrar: DNSHE", "Creation Date: 2026-02-14 11:07:00", "Registry Expiry Date: 2028-02-14 11:07:00", "Name Server: renan.ns.cloudflare.com"} {
		if !strings.Contains(raw.Body, want) {
			t.Fatalf("missing %q in:\n%s", want, raw.Body)
		}
	}
	if strings.Contains(raw.Body, "REDACTED") || strings.Contains(raw.Body, "not registered") {
		t.Fatalf("redaction or miss text leaked:\n%s", raw.Body)
	}

	free := model.NormalizedQuery{Type: model.QueryDomain, Query: "free.cc.cd", Suffix: "cc.cd", RegisteredDomain: "free.cc.cd"}
	raw, err = provider.Lookup(context.Background(), free, model.LookupOptions{})
	if err != nil || !strings.Contains(raw.Body, "Domain not registered") {
		t.Fatalf("unregistered body %q err %v", raw.Body, err)
	}
}

func TestWHOISWebSkipsBareSuffix(t *testing.T) {
	provider := NewWithClient(http.DefaultClient, DNSHEModule{BaseURL: "http://127.0.0.1:1"})
	q := model.NormalizedQuery{Type: model.QueryDomain, Query: "cc.cd", Suffix: "cc.cd"}
	if provider.Supports(q) || provider.Required(q) {
		t.Fatal("the suffix itself must not be looked up through a WHOIS Web module")
	}
}
