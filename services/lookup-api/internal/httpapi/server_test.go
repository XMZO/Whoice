package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/lookup"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/observability"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

func TestOptionsFromRequestPreservesExplicitZeroWhoisFollow(t *testing.T) {
	server := New(config.Config{WHOISFollowLimit: 2}, nil, nil, nil)
	request := httptest.NewRequest("GET", "/api/lookup?query=example.com&whois_follow=0", nil)

	opts, err := server.optionsFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if opts.WHOISFollow != 0 {
		t.Fatalf("whois follow: got %d want 0", opts.WHOISFollow)
	}
}

func TestRateLimitKeyTrustsForwardedForWhenConfigured(t *testing.T) {
	server := New(config.Config{TrustProxy: true}, nil, nil, nil)
	request := httptest.NewRequest("GET", "/api/lookup?query=example.com", nil)
	request.RemoteAddr = "172.18.0.2:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.10, 172.18.0.3")

	if got := server.rateLimitKey(request); got != "203.0.113.10" {
		t.Fatalf("rate limit key: got %q want forwarded client", got)
	}
}

func TestRateLimitKeyIgnoresForwardedForByDefault(t *testing.T) {
	server := New(config.Config{}, nil, nil, nil)
	request := httptest.NewRequest("GET", "/api/lookup?query=example.com", nil)
	request.RemoteAddr = "172.18.0.2:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")

	if got := server.rateLimitKey(request); got != "172.18.0.2" {
		t.Fatalf("rate limit key: got %q want remote addr", got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	stats := observability.NewStats()
	stats.RecordLookup(true, 123)
	stats.RecordProviders([]observability.ProviderTraceView{{Source: "rdap", Status: "ok", ElapsedMs: 45}})
	server := New(config.Config{MetricsEnabled: true}, nil, nil, stats)
	request := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, `whoice_lookup_requests_total{outcome="success"} 1`) {
		t.Fatalf("missing lookup metric in %q", body)
	}
	if !strings.Contains(body, `whoice_provider_requests_total{outcome="success",provider="rdap"} 1`) {
		t.Fatalf("missing provider metric in %q", body)
	}
	if !strings.Contains(body, `whoice_lookup_latency_milliseconds_bucket{le="250"} 1`) {
		t.Fatalf("missing lookup histogram in %q", body)
	}
	if !strings.Contains(body, `whoice_provider_latency_milliseconds_bucket{le="50",provider="rdap"} 1`) {
		t.Fatalf("missing provider histogram in %q", body)
	}
}

func TestMetricsEndpointCanBeDisabled(t *testing.T) {
	server := New(config.Config{}, nil, nil, observability.NewStats())
	request := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", response.Code)
	}
}

func TestICPEndpointNormalizesToRegisteredDomainAndHidesBlocklist(t *testing.T) {
	cfg := runtimeFixtureConfig(false, false, false)
	cfg.ICPEnabled = true
	cfg.ICPBlocklist = []string{"example.com"}
	server := New(cfg, nil, nil, observability.NewStats())
	request := httptest.NewRequest(http.MethodGet, "/api/icp?domain=www.example.com", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", response.Code, response.Body.String())
	}
	var body struct {
		OK     bool `json:"ok"`
		Result struct {
			Domain  string `json:"domain"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Result.Domain != "example.com" || body.Result.Status != "not_found" {
		t.Fatalf("body: %#v", body)
	}
	if strings.Contains(strings.ToLower(body.Result.Message), "block") || strings.Contains(body.Result.Message, "屏蔽") {
		t.Fatalf("block reason leaked: %q", body.Result.Message)
	}
}

func TestLookupReportsSuccessEvent(t *testing.T) {
	rdapBody := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["active"]}`
	cfg := runtimeFixtureConfig(true, false, false)
	cfg.Reporter = "test"
	reporter := newCaptureReporter()
	service := lookup.NewService(cfg, []providers.Provider{runtimeFixtureProvider{
		source:       model.SourceRDAP,
		server:       "https://rdap.example.test/domain/",
		body:         rdapBody,
		contentType:  "application/rdap+json",
		elapsedMs:    7,
		supportTypes: []model.QueryType{model.QueryDomain},
	}}, parsers.NewRegistry(parsers.RDAPParser{}))
	server := New(cfg, service, nil, observability.NewStats())
	server.reporter = reporter
	request := httptest.NewRequest(http.MethodGet, "/api/lookup?query=example.com&rdap=true&whois=false", nil)
	request.Header.Set("X-Request-ID", "report-success")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", response.Code, response.Body.String())
	}
	event := reporter.wait(t)
	if !event.OK || event.TraceID != "report-success" || event.NormalizedQuery != "example.com" || len(event.Providers) != 1 {
		t.Fatalf("unexpected report event: %#v", event)
	}
}

func TestLookupReportsInvalidQueryEvent(t *testing.T) {
	cfg := runtimeFixtureConfig(true, true, false)
	cfg.Reporter = "test"
	reporter := newCaptureReporter()
	service := lookup.NewService(cfg, nil, parsers.NewRegistry())
	server := New(cfg, service, nil, observability.NewStats())
	server.reporter = reporter
	request := httptest.NewRequest(http.MethodGet, "/api/lookup?query=example_com", nil)
	request.Header.Set("X-Request-ID", "report-invalid")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400, body=%s", response.Code, response.Body.String())
	}
	event := reporter.wait(t)
	if event.OK || event.TraceID != "report-invalid" || event.ErrorCode != "invalid_query" {
		t.Fatalf("unexpected report event: %#v", event)
	}
}

func TestOptionsFromRequestUsesDefaultWhoisFollowSentinel(t *testing.T) {
	server := New(config.Config{WHOISFollowLimit: 2}, nil, nil, nil)
	request := httptest.NewRequest("GET", "/api/lookup?query=example.com&ai=1", nil)

	opts, err := server.optionsFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if opts.WHOISFollow != -1 {
		t.Fatalf("whois follow sentinel: got %d want -1", opts.WHOISFollow)
	}
	if !opts.ForceAI {
		t.Fatal("force ai option was not parsed")
	}
}

func TestLookupDoesNotRunAIInline(t *testing.T) {
	body := strings.Join([]string{
		"Domain Name: EXAMPLE.CN",
		"Registrant: Example Owner",
		"Registrant Contact Email: owner@example.cn",
		"Sponsoring Registrar: Example Registrar",
		"Name Server: ns1.example.cn",
		"Registration Time: 2020-01-02 03:04:05",
	}, "\n")
	cfg := runtimeFixtureConfig(false, true, false)
	cfg.AIEnabled = true
	cfg.AIBaseURL = "http://127.0.0.1:1/v1"
	cfg.AIModel = "test-model"
	service := lookup.NewService(cfg, []providers.Provider{runtimeFixtureProvider{
		source:       model.SourceWHOIS,
		server:       "whois.example.test",
		body:         body,
		contentType:  "text/plain; charset=utf-8",
		supportTypes: []model.QueryType{model.QueryDomain},
	}}, parsers.NewRegistry(parsers.WHOISParser{}, parsers.CNWHOISParser{}))
	server := New(cfg, service, nil, observability.NewStats())
	request := httptest.NewRequest(http.MethodGet, "/api/lookup?query=example.cn&whois=1&ai=1", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", response.Code, response.Body.String())
	}
	var payload model.APIResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Result == nil {
		t.Fatal("missing result")
	}
	if payload.Result.Meta.AI != nil {
		t.Fatalf("main lookup should not run AI inline: %#v", payload.Result.Meta.AI)
	}
	if payload.Result.Registrant.Email != "owner@example.cn" {
		t.Fatalf("deterministic registrant email: got %q", payload.Result.Registrant.Email)
	}
}

func TestLookupAIEndpointAppliesAnalysis(t *testing.T) {
	aiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected AI path: %s", r.URL.Path)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"role": "assistant",
						"content": `{
							"registrant": {
								"name": "AI Owner",
								"email": "owner@example.cn",
								"confidence": 0.93,
								"evidence": "Registrant Contact Email: owner@example.cn"
							}
						}`,
					},
				},
			},
		})
	}))
	defer aiServer.Close()

	cfg := runtimeFixtureConfig(false, false, false)
	cfg.AIEnabled = true
	cfg.AIBaseURL = aiServer.URL
	cfg.AIModel = "test-model"
	cfg.AICacheTTL = 0
	service := lookup.NewService(cfg, nil, parsers.NewRegistry())
	server := New(cfg, service, nil, observability.NewStats())
	payload := map[string]any{
		"force": true,
		"result": model.LookupResult{
			Query:           "example.cn",
			NormalizedQuery: "example.cn",
			Type:            model.QueryDomain,
			Status:          model.StatusRegistered,
			Raw: model.RawData{
				WHOIS: "Registrant: AI Owner\nRegistrant Contact Email: owner@example.cn",
			},
			Meta: model.ResultMeta{},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/lookup/ai", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", response.Code, response.Body.String())
	}
	var apiResponse model.APIResponse
	if err := json.Unmarshal(response.Body.Bytes(), &apiResponse); err != nil {
		t.Fatal(err)
	}
	if apiResponse.Result == nil || apiResponse.Result.Meta.AI == nil {
		t.Fatalf("missing AI result: %#v", apiResponse)
	}
	if apiResponse.Result.Meta.AI.Status != "ok" {
		t.Fatalf("AI status: %#v", apiResponse.Result.Meta.AI)
	}
	if apiResponse.Result.Registrant.Email != "owner@example.cn" || apiResponse.Result.Registrant.Name != "AI Owner" {
		t.Fatalf("registrant: %#v", apiResponse.Result.Registrant)
	}
}

func TestInvalidQueryReturnsBadRequest(t *testing.T) {
	service := lookup.NewService(config.Config{}, nil, parsers.NewRegistry())
	server := New(config.Config{}, service, nil, observability.NewStats())
	request := httptest.NewRequest(http.MethodGet, "/api/lookup?query=example_com", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400, body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"invalid_query"`) {
		t.Fatalf("body: %s", response.Body.String())
	}
}

func TestLookupNormalizesSeparatorTyposBeforeIDNA(t *testing.T) {
	service := lookup.NewService(config.Config{LookupTimeout: 2_000_000_000, ProviderTimeout: 2_000_000_000}, nil, parsers.NewRegistry())
	server := New(config.Config{}, service, nil, observability.NewStats())
	request := httptest.NewRequest(http.MethodGet, "/api/lookup?query=example,com", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want provider failure after successful normalization, body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "U+002C") || strings.Contains(response.Body.String(), "idna:") {
		t.Fatalf("query was not normalized before IDNA: %s", response.Body.String())
	}
}

func TestOptionsFromRequestNormalizesServerSeparators(t *testing.T) {
	server := New(config.Config{AllowCustomServers: false}, nil, nil, nil)
	request := httptest.NewRequest("GET", "/api/lookup?query=example.com&rdap_server=https%3A%2F%2Frdap%EF%BC%8Cexample%E3%80%82com&whois_server=whois%2Cexample%EF%BC%8Ecom", nil)

	opts, err := server.optionsFromRequest(request)
	if err == nil {
		t.Fatal("expected custom server to be rejected after normalization")
	}
	if opts.RDAPServer != "https://rdap.example.com" || opts.WHOISServer != "whois.example.com" {
		body, _ := json.Marshal(opts)
		t.Fatalf("server options were not normalized: %s", body)
	}
}

func TestRuntimeLookupResponsesMatchSchemaFixtures(t *testing.T) {
	rdapDomainBody := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["active"],"port43":"whois.example.test","nameservers":[{"ldhName":"A.IANA-SERVERS.NET"}],"secureDNS":{"delegationSigned":false},"entities":[{"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"376"}],"vcardArray":["vcard",[["fn",{},"text","Example Registrar, Inc."]]]}]}`
	whoisDomainBody := strings.Join([]string{
		"Domain Name: EXAMPLE.NET",
		"Registrar: Example Registrar, Inc.",
		"Registrar IANA ID: 9999",
		"Registrar URL: https://registrar.example/",
		"Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
		"Name Server: NS1.EXAMPLE.NET",
		"Name Server: NS2.EXAMPLE.NET",
		"DNSSEC: signedDelegation",
		"Registrant Country: US",
	}, "\n")
	whoisWebBody := strings.Join([]string{
		"Domain Name: EXAMPLE.VN",
		"Registrar: WHOIS Web Registrar",
		"Name Server: NS1.EXAMPLE.VN",
		"Status: active",
	}, "\n")
	rdapIPBody := `{"objectClassName":"ip network","startAddress":"192.0.2.0","endAddress":"192.0.2.255","name":"EXAMPLE-NET","type":"ASSIGNED PA","country":"ZZ","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example Network Operations"],["country-name",{},"text","ZZ"]]]}]}`
	rdapIPv6Body := `{"objectClassName":"ip network","startAddress":"2001:db8::","endAddress":"2001:db8::ffff","name":"EXAMPLE-V6","type":"ALLOCATED-BY-RIR","country":"ZZ","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example IPv6 Operations"],["country-name",{},"text","ZZ"]]]}]}`
	rdapASNBody := `{"objectClassName":"autnum","startAutnum":64496,"endAutnum":64496,"name":"EXAMPLE-AS","country":"ZZ","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example ASN Operations"],["country-name",{},"text","ZZ"]]]}]}`
	rdapCIDRBody := `{"objectClassName":"ip network","startAddress":"2001:db8::","endAddress":"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff","name":"EXAMPLE-CIDR","type":"ALLOCATED-BY-RIR","country":"ZZ","status":["active"],"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example CIDR Operations"],["country-name",{},"text","ZZ"]]]}]}`

	cases := []struct {
		name       string
		file       string
		request    string
		traceID    string
		wantStatus int
		cfg        config.Config
		providers  []providers.Provider
		parsers    *parsers.Registry
	}{
		{
			name:       "rdap-domain",
			file:       "lookup-rdap-domain.response.json",
			request:    "/api/lookup?query=example.com&rdap=true&whois=false",
			traceID:    "runtime-schema-rdap-domain",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(true, false, false),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceRDAP,
				server:       "https://rdap.example.test/domain/",
				body:         rdapDomainBody,
				contentType:  "application/rdap+json",
				elapsedMs:    7,
				supportTypes: []model.QueryType{model.QueryDomain},
			}},
			parsers: parsers.NewRegistry(parsers.RDAPParser{}),
		},
		{
			name:       "whois-domain",
			file:       "lookup-whois-domain.response.json",
			request:    "/api/lookup?query=example.net&rdap=false&whois=true",
			traceID:    "runtime-schema-whois-domain",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(false, true, false),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceWHOIS,
				server:       "whois.example.test",
				body:         whoisDomainBody,
				contentType:  "text/plain; charset=utf-8",
				elapsedMs:    11,
				supportTypes: []model.QueryType{model.QueryDomain},
			}},
			parsers: parsers.NewRegistry(parsers.WHOISParser{}),
		},
		{
			name:       "whoisweb-domain",
			file:       "lookup-whoisweb-domain.response.json",
			request:    "/api/lookup?query=example.vn&rdap=false&whois=true",
			traceID:    "runtime-schema-whoisweb-domain",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(false, false, true),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceWHOISWeb,
				server:       "https://whoisweb.example.test/vn",
				body:         whoisWebBody,
				contentType:  "text/plain; charset=utf-8",
				elapsedMs:    13,
				supportTypes: []model.QueryType{model.QueryDomain},
			}},
			parsers: parsers.NewRegistry(parsers.WHOISParser{}),
		},
		{
			name:       "rdap-ipv4",
			file:       "lookup-rdap-ipv4.response.json",
			request:    "/api/lookup?query=192.0.2.1&rdap=true&whois=false",
			traceID:    "runtime-schema-rdap-ipv4",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(true, false, false),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceRDAP,
				server:       "https://rdap.example.test/ip/",
				body:         rdapIPBody,
				contentType:  "application/rdap+json",
				elapsedMs:    5,
				supportTypes: []model.QueryType{model.QueryIPv4},
			}},
			parsers: parsers.NewRegistry(parsers.RDAPParser{}),
		},
		{
			name:       "rdap-ipv6",
			file:       "lookup-rdap-ipv6.response.json",
			request:    "/api/lookup?query=2001:db8::1&rdap=true&whois=false",
			traceID:    "runtime-schema-rdap-ipv6",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(true, false, false),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceRDAP,
				server:       "https://rdap.example.test/ip/",
				body:         rdapIPv6Body,
				contentType:  "application/rdap+json",
				elapsedMs:    6,
				supportTypes: []model.QueryType{model.QueryIPv6},
			}},
			parsers: parsers.NewRegistry(parsers.RDAPParser{}),
		},
		{
			name:       "rdap-asn",
			file:       "lookup-rdap-asn.response.json",
			request:    "/api/lookup?query=AS64496&rdap=true&whois=false",
			traceID:    "runtime-schema-rdap-asn",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(true, false, false),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceRDAP,
				server:       "https://rdap.example.test/autnum/",
				body:         rdapASNBody,
				contentType:  "application/rdap+json",
				elapsedMs:    4,
				supportTypes: []model.QueryType{model.QueryASN},
			}},
			parsers: parsers.NewRegistry(parsers.RDAPParser{}),
		},
		{
			name:       "rdap-cidr",
			file:       "lookup-rdap-cidr.response.json",
			request:    "/api/lookup?query=2001:db8::/32&rdap=true&whois=false",
			traceID:    "runtime-schema-rdap-cidr",
			wantStatus: http.StatusOK,
			cfg:        runtimeFixtureConfig(true, false, false),
			providers: []providers.Provider{runtimeFixtureProvider{
				source:       model.SourceRDAP,
				server:       "https://rdap.example.test/ip/",
				body:         rdapCIDRBody,
				contentType:  "application/rdap+json",
				elapsedMs:    8,
				supportTypes: []model.QueryType{model.QueryCIDR},
			}},
			parsers: parsers.NewRegistry(parsers.RDAPParser{}),
		},
		{
			name:       "invalid-query",
			file:       "lookup-invalid-query.response.json",
			request:    "/api/lookup?query=example_com",
			traceID:    "runtime-schema-invalid-query",
			wantStatus: http.StatusBadRequest,
			cfg:        runtimeFixtureConfig(true, true, false),
			parsers:    parsers.NewRegistry(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := lookup.NewService(tc.cfg, tc.providers, tc.parsers)
			server := New(tc.cfg, service, nil, observability.NewStats())
			request := httptest.NewRequest(http.MethodGet, tc.request, nil)
			request.Header.Set("X-Request-ID", tc.traceID)
			response := httptest.NewRecorder()

			server.Handler().ServeHTTP(response, request.WithContext(context.Background()))

			if response.Code != tc.wantStatus {
				t.Fatalf("status: got %d want %d, body=%s", response.Code, tc.wantStatus, response.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			normalizeRuntimeFixturePayload(payload)
			got, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')

			path := filepath.Join("..", "..", "..", "..", "packages", "fixtures", "api-runtime", tc.file)
			if os.Getenv("WHOICE_UPDATE_RUNTIME_FIXTURES") == "1" {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("runtime API fixture %s drifted; run with WHOICE_UPDATE_RUNTIME_FIXTURES=1 after reviewing the response\n--- got ---\n%s\n--- want ---\n%s", tc.file, got, want)
			}
		})
	}
}

func runtimeFixtureConfig(rdapEnabled, whoisEnabled, whoisWebEnabled bool) config.Config {
	return config.Config{
		LookupTimeout:   5 * time.Second,
		ProviderTimeout: 5 * time.Second,
		RDAPEnabled:     rdapEnabled,
		WHOISEnabled:    whoisEnabled,
		WHOISWebEnabled: whoisWebEnabled,
		EnrichEPP:       false,
		EnrichRegistrar: false,
		EnrichDNS:       false,
		EnrichDNSViz:    false,
		EnrichBrands:    false,
		ICPTimeout:      time.Second,
		ICPCacheTTL:     time.Hour,
		ICPPageSize:     10,
		MetricsEnabled:  true,
	}
}

type runtimeFixtureProvider struct {
	source       model.SourceName
	server       string
	body         string
	contentType  string
	statusCode   int
	elapsedMs    int64
	supportTypes []model.QueryType
}

func (p runtimeFixtureProvider) Name() model.SourceName {
	return p.source
}

func (p runtimeFixtureProvider) Supports(q model.NormalizedQuery) bool {
	for _, queryType := range p.supportTypes {
		if q.Type == queryType {
			return true
		}
	}
	return len(p.supportTypes) == 0
}

func (p runtimeFixtureProvider) Lookup(_ context.Context, q model.NormalizedQuery, _ model.LookupOptions) (*model.RawResponse, error) {
	statusCode := p.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	return &model.RawResponse{
		Source:      p.source,
		Server:      p.server,
		Query:       q.Query,
		Body:        p.body,
		ContentType: p.contentType,
		StatusCode:  statusCode,
		ElapsedMs:   p.elapsedMs,
	}, nil
}

func normalizeRuntimeFixturePayload(payload map[string]any) {
	if meta, ok := payload["meta"].(map[string]any); ok {
		meta["elapsedMs"] = 0
	}
	if result, ok := payload["result"].(map[string]any); ok {
		if meta, ok := result["meta"].(map[string]any); ok {
			meta["elapsedMs"] = 0
		}
		if dates, ok := result["dates"].(map[string]any); ok {
			if _, ok := dates["ageDays"]; ok {
				dates["ageDays"] = 0
			}
			if _, ok := dates["remainingDays"]; ok {
				dates["remainingDays"] = 0
			}
		}
	}
}

type captureReporter struct {
	events chan observability.LookupEvent
}

func newCaptureReporter() *captureReporter {
	return &captureReporter{events: make(chan observability.LookupEvent, 4)}
}

func (r *captureReporter) ReportLookup(_ context.Context, event observability.LookupEvent) {
	r.events <- event
}

func (r *captureReporter) wait(t *testing.T) observability.LookupEvent {
	t.Helper()
	select {
	case event := <-r.events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lookup report")
		return observability.LookupEvent{}
	}
}
