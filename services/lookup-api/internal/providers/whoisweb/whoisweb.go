package whoisweb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

const (
	defaultDZBaseURL = "https://api.nic.dz/v1"
	defaultLKBaseURL = "https://register.domains.lk"
	defaultMTBaseURL = "https://www.nic.org.mt"
	defaultNIBaseURL = "https://apiecommercenic.uni.edu.ni/api/v1"
	defaultPABaseURL = "https://nic.pa:8080"
	defaultVNBaseURL = "https://whois.inet.vn"
)

type Module interface {
	Name() string
	Supports(suffix string) bool
	Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error)
}

type ModuleResult struct {
	Body        string
	Endpoint    string
	ContentType string
	StatusCode  int
}

type Provider struct {
	client  *http.Client
	modules []Module
}

func New() *Provider {
	return NewWithClient(http.DefaultClient, DefaultModules()...)
}

func NewWithClient(client *http.Client, modules ...Module) *Provider {
	if client == nil {
		client = http.DefaultClient
	}
	return &Provider{client: client, modules: modules}
}

func DefaultModules() []Module {
	return []Module{
		NewNoticeModule(map[string]string{
			"ao": "https://www.dns.ao/ao/whois/",
			"az": "https://whois.az",
			"ba": "https://nic.ba/?culture=en",
			"cy": "https://registry.nic.cy/cy-ui/home",
			"dj": "https://dot.dj",
			"gq": "http://www.dominio.gq/en/whois.html",
			"py": "https://www.nic.py/consultdompy.php",
		}),
		DZModule{BaseURL: defaultDZBaseURL},
		LKModule{BaseURL: defaultLKBaseURL},
		MTModule{BaseURL: defaultMTBaseURL},
		NIModule{BaseURL: defaultNIBaseURL},
		PAModule{BaseURL: defaultPABaseURL},
		VNModule{BaseURL: defaultVNBaseURL},
	}
}

func (p *Provider) Name() model.SourceName {
	return model.SourceWHOISWeb
}

func (p *Provider) Supports(q model.NormalizedQuery) bool {
	if q.Type != model.QueryDomain {
		return false
	}
	return p.findModule(q.Suffix) != nil
}

func (p *Provider) Lookup(ctx context.Context, q model.NormalizedQuery, _ model.LookupOptions) (*model.RawResponse, error) {
	start := time.Now()
	module := p.findModule(q.Suffix)
	if module == nil {
		return nil, fmt.Errorf("no WHOIS Web fallback module for .%s", q.Suffix)
	}
	result, err := module.Lookup(ctx, p.client, q)
	if err != nil {
		return nil, err
	}
	if result == nil || strings.TrimSpace(result.Body) == "" {
		return nil, errors.New("empty WHOIS Web response")
	}
	return &model.RawResponse{
		Source:      model.SourceWHOISWeb,
		Server:      result.Endpoint,
		Query:       q.Query,
		Body:        result.Body,
		ContentType: result.ContentType,
		StatusCode:  result.StatusCode,
		ElapsedMs:   time.Since(start).Milliseconds(),
	}, nil
}

func (p *Provider) findModule(suffix string) Module {
	suffix = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suffix), "."))
	for _, module := range p.modules {
		if module.Supports(suffix) {
			return module
		}
	}
	return nil
}

type NoticeModule struct {
	targets map[string]string
}

func NewNoticeModule(targets map[string]string) NoticeModule {
	copied := make(map[string]string, len(targets))
	for suffix, target := range targets {
		copied[strings.ToLower(strings.TrimPrefix(suffix, "."))] = target
	}
	return NoticeModule{targets: copied}
}

func (m NoticeModule) Name() string { return "notice" }

func (m NoticeModule) Supports(suffix string) bool {
	_, ok := m.targets[strings.ToLower(strings.TrimPrefix(suffix, "."))]
	return ok
}

func (m NoticeModule) Lookup(_ context.Context, _ *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	target := m.targets[strings.ToLower(q.Suffix)]
	if target == "" {
		return nil, fmt.Errorf("notice target missing for .%s", q.Suffix)
	}
	return &ModuleResult{
		Body:        fmt.Sprintf("WHOIS Web fallback notice: Please visit %s for %s.", target, q.Query),
		Endpoint:    target,
		ContentType: "text/plain; charset=utf-8",
	}, nil
}

type DZModule struct {
	BaseURL string
}

func (m DZModule) Name() string { return "dz" }

func (m DZModule) Supports(suffix string) bool {
	suffix = strings.ToLower(strings.TrimPrefix(suffix, "."))
	return suffix == "dz" || suffix == "xn--lgbbat1ad8j"
}

func (m DZModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultDZBaseURL
	}
	segment := "/"
	if strings.EqualFold(q.Suffix, "xn--lgbbat1ad8j") {
		segment = "/arabic/"
	}
	endpoint := baseURL + segment + "domains/" + url.PathEscape(q.Query)
	var payload dzResponse
	statusCode, contentType, err := getJSON(ctx, client, endpoint, &payload)
	if err != nil {
		return nil, err
	}
	body := payload.toWHOIS()
	return &ModuleResult{
		Body:        body,
		Endpoint:    endpoint,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}

type dzResponse struct {
	Title             string `json:"title"`
	DomainName        string `json:"domainName"`
	Registrar         string `json:"registrar"`
	CreationDate      string `json:"creationDate"`
	RegistrantOrg     string `json:"orgName"`
	RegistrantAddress string `json:"addressOrg"`
	AdminName         string `json:"contactAdm"`
	AdminOrg          string `json:"orgNameAdm"`
	AdminAddress      string `json:"addressAdm"`
	AdminPhone        string `json:"phoneAdm"`
	AdminFax          string `json:"faxAdm"`
	AdminEmail        string `json:"emailAdm"`
	TechName          string `json:"contactTech"`
	TechOrg           string `json:"orgNameTech"`
	TechAddress       string `json:"addressTech"`
	TechPhone         string `json:"phoneTech"`
	TechFax           string `json:"faxTech"`
	TechEmail         string `json:"emailTech"`
}

func (r dzResponse) toWHOIS() string {
	if strings.TrimSpace(r.Title) != "" {
		return strings.TrimSpace(r.Title)
	}
	var builder strings.Builder
	writeLine(&builder, "Domain Name", r.DomainName)
	writeLine(&builder, "Registrar", r.Registrar)
	writeLine(&builder, "Creation Date", r.CreationDate)
	writeLine(&builder, "Registrant Organization", r.RegistrantOrg)
	writeLine(&builder, "Registrant Address", r.RegistrantAddress)
	writeLine(&builder, "Admin Name", r.AdminName)
	writeLine(&builder, "Admin Organization", r.AdminOrg)
	writeLine(&builder, "Admin Address", r.AdminAddress)
	writeLine(&builder, "Admin Phone", r.AdminPhone)
	writeLine(&builder, "Admin Fax", r.AdminFax)
	writeLine(&builder, "Admin Email", r.AdminEmail)
	writeLine(&builder, "Tech Name", r.TechName)
	writeLine(&builder, "Tech Organization", r.TechOrg)
	writeLine(&builder, "Tech Address", r.TechAddress)
	writeLine(&builder, "Tech Phone", r.TechPhone)
	writeLine(&builder, "Tech Fax", r.TechFax)
	writeLine(&builder, "Tech Email", r.TechEmail)
	return strings.TrimSpace(builder.String())
}

type LKModule struct {
	BaseURL string
}

func (m LKModule) Name() string { return "lk" }

func (m LKModule) Supports(suffix string) bool {
	return strings.EqualFold(strings.TrimPrefix(suffix, "."), "lk")
}

func (m LKModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultLKBaseURL
	}
	endpoint := baseURL + "/proxy/domains/single-search?keyword=" + url.QueryEscape(q.Query)
	var payload lkResponse
	statusCode, contentType, err := getJSON(ctx, client, endpoint, &payload)
	if err != nil {
		return nil, err
	}
	return &ModuleResult{
		Body:        payload.toWHOIS(q.Query),
		Endpoint:    endpoint,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}

type lkResponse struct {
	Result struct {
		DomainAvailability *struct {
			Message    string `json:"message"`
			DomainName string `json:"domainName"`
			DomainInfo *struct {
				ExpireDate   string `json:"expireDate"`
				RegisteredTo string `json:"registeredTo"`
			} `json:"domainInfo"`
		} `json:"domainAvailability"`
	} `json:"result"`
}

func (r lkResponse) toWHOIS(domain string) string {
	availability := r.Result.DomainAvailability
	if availability == nil {
		return ""
	}
	message := strings.TrimSpace(availability.Message)
	if strings.EqualFold(message, "Domain name you searched is restricted") {
		message = "Domain name is restricted"
	}
	var builder strings.Builder
	writeLine(&builder, "Message", message)
	writeLine(&builder, "Domain Name", firstNonEmpty(availability.DomainName, domain))
	if availability.DomainInfo != nil {
		writeLine(&builder, "Registry Expiry Date", normalizeLKDate(availability.DomainInfo.ExpireDate))
		writeLine(&builder, "Registrant Name", availability.DomainInfo.RegisteredTo)
	}
	return strings.TrimSpace(builder.String())
}

var lkOrdinalDayPattern = regexp.MustCompile(`\b(\d{1,2})(st|nd|rd|th)\b`)

func normalizeLKDate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	cleaned := lkOrdinalDayPattern.ReplaceAllString(value, "$1")
	for _, layout := range []string{"Monday, 2 January, 2006", "2 January, 2006", "2006-01-02"} {
		parsed, err := time.Parse(layout, cleaned)
		if err == nil {
			return parsed.Format("2006-01-02")
		}
	}
	return value
}

type MTModule struct {
	BaseURL string
}

func (m MTModule) Name() string { return "mt" }

func (m MTModule) Supports(suffix string) bool {
	return strings.EqualFold(strings.TrimPrefix(suffix, "."), "mt")
}

func (m MTModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultMTBaseURL
	}
	endpoint := baseURL + "/dotmt/whois/?" + url.QueryEscape(q.Query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("WHOIS Web HTTP %d", resp.StatusCode)
	}
	whois := extractPreText(string(body))
	return &ModuleResult{
		Body:        whois,
		Endpoint:    endpoint,
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
	}, nil
}

var preBlockPattern = regexp.MustCompile(`(?is)<pre\b[^>]*>(.*?)</pre>`)
var htmlTagPattern = regexp.MustCompile(`(?is)<[^>]+>`)

func extractPreText(body string) string {
	matches := preBlockPattern.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	text := htmlTagPattern.ReplaceAllString(matches[1], "")
	return strings.TrimSpace(html.UnescapeString(text))
}

type NIModule struct {
	BaseURL string
}

func (m NIModule) Name() string { return "ni" }

func (m NIModule) Supports(suffix string) bool {
	return strings.EqualFold(strings.TrimPrefix(suffix, "."), "ni")
}

func (m NIModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultNIBaseURL
	}
	endpoint := baseURL + "/dominios/whois?dominio=" + url.QueryEscape(q.Query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return &ModuleResult{
			Body:        "Domain not found",
			Endpoint:    endpoint,
			ContentType: resp.Header.Get("Content-Type"),
			StatusCode:  resp.StatusCode,
		}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("WHOIS Web HTTP %d", resp.StatusCode)
	}
	var payload niResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &ModuleResult{
		Body:        payload.toWHOIS(q.Query),
		Endpoint:    endpoint,
		ContentType: resp.Header.Get("Content-Type"),
		StatusCode:  resp.StatusCode,
	}, nil
}

type niResponse struct {
	Data *struct {
		ExpirationDate string `json:"fechaExpiracion"`
		Client         string `json:"cliente"`
		Address        string `json:"direccion"`
	} `json:"datos"`
	Contacts *struct {
		Type  string `json:"tipoContacto"`
		Name  string `json:"nombre"`
		Email []struct {
			Value string `json:"value"`
		} `json:"correoElectronico"`
		Phone    string `json:"telefono"`
		Cellular string `json:"celular"`
	} `json:"contactos"`
}

func (r niResponse) toWHOIS(domain string) string {
	var builder strings.Builder
	writeLine(&builder, "Domain Name", domain)
	if r.Data != nil {
		writeLine(&builder, "Registry Expiry Date", r.Data.ExpirationDate)
		writeLine(&builder, "Registrant Name", r.Data.Client)
		writeLine(&builder, "Registrant Address", r.Data.Address)
	}
	if r.Contacts != nil {
		var emails []string
		for _, email := range r.Contacts.Email {
			if strings.TrimSpace(email.Value) != "" {
				emails = append(emails, strings.TrimSpace(email.Value))
			}
		}
		writeLine(&builder, "Contact Type", r.Contacts.Type)
		writeLine(&builder, "Contact Name", r.Contacts.Name)
		writeLine(&builder, "Contact Email", strings.Join(emails, ","))
		writeLine(&builder, "Contact Phone", r.Contacts.Phone)
		writeLine(&builder, "Contact Cellphone", r.Contacts.Cellular)
	}
	return strings.TrimSpace(builder.String())
}

type PAModule struct {
	BaseURL string
}

func (m PAModule) Name() string { return "pa" }

func (m PAModule) Supports(suffix string) bool {
	return strings.EqualFold(strings.TrimPrefix(suffix, "."), "pa")
}

func (m PAModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultPABaseURL
	}
	endpoint := baseURL + "/whois/" + url.PathEscape(q.Query)
	var payload paResponse
	statusCode, contentType, err := getJSONAllow404(ctx, client, endpoint, &payload)
	if err != nil {
		return nil, err
	}
	if statusCode == http.StatusNotFound {
		return &ModuleResult{
			Body:        "Domain not found",
			Endpoint:    endpoint,
			ContentType: contentType,
			StatusCode:  statusCode,
		}, nil
	}
	return &ModuleResult{
		Body:        payload.toWHOIS(q.Query),
		Endpoint:    endpoint,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}

type paResponse struct {
	Message string `json:"mensaje"`
	Payload *struct {
		DomainName     string   `json:"Dominio"`
		UpdatedDate    string   `json:"fecha_actualizacion"`
		CreationDate   string   `json:"fecha_creacion"`
		ExpirationDate string   `json:"fecha_expiracion"`
		Status         string   `json:"Estatus"`
		Nameservers    []string `json:"NS"`
		Holder         *struct {
			Contact *struct {
				Name        string `json:"nombre"`
				Address1    string `json:"direccion1"`
				Address2    string `json:"direccion2"`
				City        string `json:"ciudad"`
				Province    string `json:"estado"`
				Country     string `json:"ubicacion"`
				Phone       string `json:"telefono"`
				OfficePhone string `json:"telefono_oficina"`
				Email       string `json:"email"`
			} `json:"contacto"`
		} `json:"titular"`
	} `json:"payload"`
}

func (r paResponse) toWHOIS(domain string) string {
	if strings.TrimSpace(r.Message) != "" && r.Payload == nil {
		return strings.TrimSpace(r.Message)
	}
	if r.Payload == nil {
		return ""
	}
	payload := r.Payload
	var builder strings.Builder
	writeLine(&builder, "Domain Name", firstNonEmpty(payload.DomainName, domain))
	writeLine(&builder, "Updated Date", payload.UpdatedDate)
	writeLine(&builder, "Creation Date", payload.CreationDate)
	writeLine(&builder, "Registry Expiry Date", payload.ExpirationDate)
	writeLine(&builder, "Domain Status", payload.Status)
	for _, nameServer := range payload.Nameservers {
		writeLine(&builder, "Name Server", nameServer)
	}
	if payload.Holder != nil && payload.Holder.Contact != nil {
		contact := payload.Holder.Contact
		writeLine(&builder, "Registrant Name", contact.Name)
		writeLine(&builder, "Registrant Street", strings.Join(nonEmptyStrings(contact.Address1, contact.Address2), ", "))
		writeLine(&builder, "Registrant City", contact.City)
		writeLine(&builder, "Registrant State/Province", contact.Province)
		writeLine(&builder, "Registrant Country", contact.Country)
		writeLine(&builder, "Registrant Phone", strings.Join(nonEmptyStrings(contact.Phone, contact.OfficePhone), ", "))
		writeLine(&builder, "Registrant Email", contact.Email)
	}
	return strings.TrimSpace(builder.String())
}

type VNModule struct {
	BaseURL string
}

func (m VNModule) Name() string { return "vn" }

func (m VNModule) Supports(suffix string) bool {
	return strings.EqualFold(strings.TrimPrefix(suffix, "."), "vn")
}

func (m VNModule) Lookup(ctx context.Context, client *http.Client, q model.NormalizedQuery) (*ModuleResult, error) {
	baseURL := strings.TrimRight(m.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultVNBaseURL
	}
	endpoint := baseURL + "/api/whois/domainspecify/" + url.PathEscape(q.Query)
	var payload vnResponse
	statusCode, contentType, err := getJSON(ctx, client, endpoint, &payload)
	if err != nil {
		return nil, err
	}

	if payload.Code == "1" {
		availabilityEndpoint := baseURL + "/api/domain/checkavailable"
		_, _, _ = postJSON(ctx, client, availabilityEndpoint, map[string]string{"name": q.Query}, &payload)
	}

	body := payload.toWHOIS(q.Query)
	return &ModuleResult{
		Body:        body,
		Endpoint:    endpoint,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}

type vnResponse struct {
	Code           string   `json:"code"`
	DomainName     string   `json:"domainName"`
	Registrar      string   `json:"registrar"`
	CreationDate   string   `json:"creationDate"`
	ExpirationDate string   `json:"expirationDate"`
	Status         []string `json:"status"`
	NameServer     []string `json:"nameServer"`
	RegistrantName string   `json:"registrantName"`
	DNSSEC         string   `json:"DNSSEC"`
	RawText        string   `json:"rawtext"`
	Availability   string   `json:"availability"`
	Message        string   `json:"message"`
}

func (r vnResponse) toWHOIS(domain string) string {
	var builder strings.Builder
	switch r.Availability {
	case "available":
		builder.WriteString("The domain name has not been registered\n")
	case "notavailable":
		builder.WriteString("The domain " + domain + " cannot be registered\n")
		if r.Message != "" {
			builder.WriteString(r.Message + "\n")
		}
	}

	if r.Code != "0" {
		return strings.TrimSpace(builder.String())
	}

	writeLine(&builder, "Domain Name", firstNonEmpty(r.DomainName, domain))
	writeLine(&builder, "Registrar", r.Registrar)
	created, expires := r.dates()
	writeLine(&builder, "Creation Date", firstNonEmpty(created, r.CreationDate))
	writeLine(&builder, "Registry Expiry Date", firstNonEmpty(expires, r.ExpirationDate))
	for _, status := range r.Status {
		writeLine(&builder, "Domain Status", status)
	}
	for _, nameServer := range r.NameServer {
		writeLine(&builder, "Name Server", nameServer)
	}
	writeLine(&builder, "Registrant Name", r.RegistrantName)
	writeLine(&builder, "DNSSEC", r.DNSSEC)
	return strings.TrimSpace(builder.String())
}

func (r vnResponse) dates() (string, string) {
	if r.RawText == "" {
		return "", ""
	}
	var raw struct {
		IssuedDate  *vnDate `json:"issuedDate"`
		ExpiredDate *vnDate `json:"expiredDate"`
	}
	if err := json.Unmarshal([]byte(r.RawText), &raw); err != nil {
		return "", ""
	}
	return formatVNDate(raw.IssuedDate), formatVNDate(raw.ExpiredDate)
}

type vnDate struct {
	Year     int `json:"year"`
	Month    int `json:"month"`
	Day      int `json:"day"`
	Hour     int `json:"hour"`
	Minute   int `json:"minute"`
	Second   int `json:"second"`
	Timezone int `json:"timezone"`
}

func formatVNDate(value *vnDate) string {
	if value == nil || value.Year == 0 || value.Month == 0 || value.Day == 0 {
		return ""
	}
	location := time.FixedZone("vn-whois", value.Timezone*60)
	parsed := time.Date(value.Year, time.Month(value.Month), value.Day, value.Hour, value.Minute, value.Second, 0, location)
	return parsed.UTC().Format(time.RFC3339)
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, out any) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")
	return doJSON(client, req, out)
}

func getJSONAllow404(ctx context.Context, client *http.Client, endpoint string, out any) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")
	return doJSONWithOptions(client, req, out, true)
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, payload any, out any) (int, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "iclid=233")
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")
	return doJSON(client, req, out)
}

func doJSON(client *http.Client, req *http.Request, out any) (int, string, error) {
	return doJSONWithOptions(client, req, out, false)
}

func doJSONWithOptions(client *http.Client, req *http.Request, out any, allow404 bool) (int, string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return resp.StatusCode, resp.Header.Get("Content-Type"), err
	}
	if allow404 && resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, resp.Header.Get("Content-Type"), fmt.Errorf("WHOIS Web HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, resp.Header.Get("Content-Type"), err
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), nil
}

func writeLine(builder *strings.Builder, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	builder.WriteString(key)
	builder.WriteString(": ")
	builder.WriteString(value)
	builder.WriteByte('\n')
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}
