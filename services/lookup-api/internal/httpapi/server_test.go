package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/lookup"
	"github.com/xmzo/whoice/services/lookup-api/internal/observability"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
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

func TestOptionsFromRequestUsesDefaultWhoisFollowSentinel(t *testing.T) {
	server := New(config.Config{WHOISFollowLimit: 2}, nil, nil, nil)
	request := httptest.NewRequest("GET", "/api/lookup?query=example.com", nil)

	opts, err := server.optionsFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if opts.WHOISFollow != -1 {
		t.Fatalf("whois follow sentinel: got %d want -1", opts.WHOISFollow)
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
