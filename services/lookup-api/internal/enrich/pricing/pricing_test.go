package pricing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestApply(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
		Domain:          model.DomainInfo{Suffix: "com"},
	}

	if err := Apply(context.Background(), result, NewDefaultResolver("")); err != nil {
		t.Fatal(err)
	}

	if result.Enrichment.Pricing == nil || result.Enrichment.Pricing.Currency != "USD" {
		t.Fatalf("pricing: %#v", result.Enrichment.Pricing)
	}
}

func TestResolverUsesFirstSourceWithPricing(t *testing.T) {
	first := stubSource{name: "empty"}
	second := stubSource{
		name: "replacement",
		info: model.PricingInfo{Currency: "USD"},
		ok:   true,
	}

	info, ok, err := NewResolver(first, second).Lookup(context.Background(), "COM")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || info.Provider != "replacement" || info.Source != "replacement" {
		t.Fatalf("pricing: %#v ok=%t", info, ok)
	}
}

func TestEnricherImplementsPipelineBoundary(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
		Domain:          model.DomainInfo{Suffix: "com"},
	}
	enricher := NewEnricher(true, NewResolver(stubSource{
		name: "test-source",
		info: model.PricingInfo{Renew: floatPtr(12.34)},
		ok:   true,
	}))

	if !enricher.Enabled() || !enricher.Supports(result) {
		t.Fatal("enricher should be enabled and support domain results")
	}
	if err := enricher.Enrich(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.Enrichment.Pricing == nil || result.Enrichment.Pricing.Renew == nil {
		t.Fatalf("pricing: %#v", result.Enrichment.Pricing)
	}
}

func TestParseMiqingjuSnapshot(t *testing.T) {
	body := []byte(`{
		"success": true,
		"timestamp": "2026-05-14T11:16:08Z",
		"data": {
			".com": {
				"registration": {
					"registrar": "Z.com",
					"website": "https://web.z.com/us",
					"price": 0.01,
					"currency": "USD",
					"price_cny": 0.07
				},
				"renewal": {
					"registrar": "SAV.com",
					"website": "https://sav.com",
					"price": 10.15,
					"currency": "USD",
					"price_cny": 68.88
				}
			}
		}
	}`)

	pricing, updatedAt, err := parseMiqingjuSnapshot(body)
	if err != nil {
		t.Fatal(err)
	}
	info, ok := pricing["com"]
	if !ok {
		t.Fatalf("missing .com pricing: %#v", pricing)
	}
	if updatedAt != "2026-05-14T11:16:08Z" || info.Provider != "miqingju" || info.Source != "https://miqingju.com" {
		t.Fatalf("metadata: %#v updatedAt=%q", info, updatedAt)
	}
	if info.Register == nil || *info.Register != 0.01 || info.RegisterOffer == nil || info.RegisterOffer.Registrar != "Z.com" {
		t.Fatalf("register: %#v", info.RegisterOffer)
	}
	if info.Renew == nil || *info.Renew != 10.15 || info.RenewOffer == nil || info.RenewOffer.Registrar != "SAV.com" {
		t.Fatalf("renew: %#v", info.RenewOffer)
	}
}

func TestMiqingjuSnapshotSourceFetchesSnapshotOnce(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/snapshot" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":   true,
			"timestamp": "2026-05-14T11:16:08Z",
			"data": map[string]any{
				"com": map[string]any{
					"registration": map[string]any{
						"registrar": "Z.com",
						"price":     0.01,
						"currency":  "USD",
					},
					"renewal": map[string]any{
						"registrar": "SAV.com",
						"price":     10.15,
						"currency":  "USD",
					},
				},
			},
		})
	}))
	defer server.Close()

	source := newMiqingjuSnapshotSource(server.URL+"/snapshot", server.Client(), time.Hour)
	info, ok, err := source.Lookup(context.Background(), "com")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || info.RegisterOffer == nil || info.RenewOffer == nil {
		t.Fatalf("pricing: %#v ok=%t", info, ok)
	}
	if calls != 1 {
		t.Fatalf("calls: got %d want 1", calls)
	}
	_, _, _ = source.Lookup(context.Background(), "com")
	if calls != 1 {
		t.Fatalf("cached calls: got %d want 1", calls)
	}
}

func TestMiqingjuSnapshotSourceDoesNotBlockLookupDuringBackgroundRefresh(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":   true,
			"timestamp": "2026-05-14T11:16:08Z",
			"data":      map[string]any{},
		})
	}))
	defer server.Close()
	defer close(release)

	source := newMiqingjuSnapshotSource(server.URL, server.Client(), time.Hour)
	source.refreshAsync()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, ok, err := source.Lookup(ctx, "com")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no price while background snapshot is still refreshing")
	}
}

type stubSource struct {
	name string
	info model.PricingInfo
	ok   bool
	err  error
}

func (s stubSource) Name() string {
	return s.name
}

func (s stubSource) Lookup(context.Context, string) (model.PricingInfo, bool, error) {
	return s.info, s.ok, s.err
}

func floatPtr(value float64) *float64 {
	return &value
}
