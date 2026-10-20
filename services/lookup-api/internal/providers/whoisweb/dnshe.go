package whoisweb

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

const defaultDNSHEBaseURL = "https://www.dnshe.com"

// DNSHEModule covers the free second-level zones run by DNSHE. Their port-43
// server (whois.dnshe.com) no longer resolves; the web lookup returns JSON.
type DNSHEModule struct {
	BaseURL string
}

var dnsheSuffixes = map[string]bool{"cc.cd": true, "us.ci": true, "de5.net": true}

func (m DNSHEModule) Name() string { return "dnshe" }

// Registry: DNSHE's web lookup is the registry's own WHOIS for its zones.
func (m DNSHEModule) Registry() bool { return true }

func (m DNSHEModule) Supports(suffix string) bool {
	return dnsheSuffixes[strings.ToLower(strings.TrimPrefix(suffix, "."))]
}

func (m DNSHEModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultDNSHEBaseURL
	}
	domain := firstNonEmpty(q.RegisteredDomain, q.Query)
	endpoint := baseURL + "/whois.php?domain=" + url.QueryEscape(domain)
	var payload dnsheResponse
	statusCode, contentType, err := getJSON(ctx, client, endpoint, &payload)
	if err != nil {
		return nil, err
	}
	return &ModuleResult{
		Body:        payload.toWHOIS(domain),
		Endpoint:    endpoint,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}

type dnsheResponse struct {
	Success           bool     `json:"success"`
	Domain            string   `json:"domain"`
	Registered        bool     `json:"registered"`
	Status            string   `json:"status"`
	CreatedAt         string   `json:"created_at"`
	RegisteredAt      string   `json:"registered_at"`
	ExpiresAt         string   `json:"expires_at"`
	Registrar         string   `json:"registrar"`
	RegistrarURL      string   `json:"registrar_url"`
	RegistrantName    string   `json:"registrant_name"`
	RegistrantEmail   string   `json:"registrant_email"`
	RegistrantPhone   string   `json:"registrant_phone"`
	RegistrantCountry string   `json:"registrant_country"`
	RegistrantProv    string   `json:"registrant_province"`
	RegistrantCity    string   `json:"registrant_city"`
	PrivacyNotice     string   `json:"privacy_notice"`
	NameServers       []string `json:"name_servers"`
	DNSSEC            string   `json:"dnssec"`
	Message           string   `json:"message"`
}

func (r dnsheResponse) toWHOIS(domain string) string {
	var builder strings.Builder
	name := firstNonEmpty(r.Domain, domain)
	if !r.Registered {
		writeLine(&builder, "Domain Name", name)
		builder.WriteString("Domain not registered\n")
		return strings.TrimSpace(builder.String())
	}
	writeLine(&builder, "Domain Name", name)
	writeLine(&builder, "Domain Status", r.Status)
	writeLine(&builder, "Registrar", r.Registrar)
	writeLine(&builder, "Registrar URL", r.RegistrarURL)
	writeLine(&builder, "Creation Date", dnsheDate(firstNonEmpty(r.CreatedAt, r.RegisteredAt)))
	writeLine(&builder, "Registry Expiry Date", dnsheDate(r.ExpiresAt))
	writeLine(&builder, "Registrant Name", dnsheValue(r.RegistrantName))
	writeLine(&builder, "Registrant State/Province", dnsheValue(r.RegistrantProv))
	writeLine(&builder, "Registrant City", dnsheValue(r.RegistrantCity))
	writeLine(&builder, "Registrant Country", dnsheValue(r.RegistrantCountry))
	writeLine(&builder, "Registrant Phone", dnsheValue(r.RegistrantPhone))
	writeLine(&builder, "Registrant Email", dnsheValue(r.RegistrantEmail))
	for _, ns := range r.NameServers {
		writeLine(&builder, "Name Server", ns)
	}
	writeLine(&builder, "DNSSEC", r.DNSSEC)
	writeLine(&builder, "Remarks", r.PrivacyNotice)
	return strings.TrimSpace(builder.String())
}

// dnsheValue drops redaction placeholders.
func dnsheValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "-" || strings.Contains(strings.ToUpper(value), "REDACTED") {
		return ""
	}
	return value
}

// dnsheDate turns "2026-02-14 11:07" into a full timestamp; the API gives no
// time zone, so none is added.
func dnsheDate(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := time.Parse("2006-01-02 15:04", value); err == nil {
		return parsed.Format("2006-01-02 15:04:05")
	}
	return value
}
