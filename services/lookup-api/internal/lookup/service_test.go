package lookup

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pipeline"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	providerapi "github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

type testProvider struct {
	source model.SourceName
	raw    *model.RawResponse
	err    error
}

type blockingResolver struct {
	started chan struct{}
	release chan struct{}
}

func TestServiceRegistersPhase4EnrichmentPipeline(t *testing.T) {
	service := NewService(config.Config{
		LookupTimeout:    time.Second,
		ProviderTimeout:  time.Second,
		EnrichEPP:        true,
		EnrichRegistrar:  true,
		EnrichDNS:        true,
		EnrichDNSViz:     true,
		EnrichBrands:     true,
		EnrichPricing:    true,
		EnrichMoz:        true,
		DNSTimeout:       time.Second,
		WHOISFollowLimit: 1,
	}, nil, parsers.NewRegistry())

	got := service.enrichers.Names()
	want := []string{"epp", "dns", "dnsviz", "registrar", "brand", "pricing", "moz"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pipeline names: got %#v want %#v", got, want)
	}
}

func TestFastLookupReturnsBeforeDeferredEnrichment(t *testing.T) {
	resolver := &blockingResolver{started: make(chan struct{}), release: make(chan struct{})}
	service := NewService(config.Config{
		LookupTimeout:      time.Second,
		ProviderTimeout:    time.Second,
		RDAPEnabled:        false,
		WHOISEnabled:       true,
		WHOISFollowLimit:   1,
		LookupFastResponse: true,
		EnrichEPP:          true,
		EnrichRegistrar:    true,
		EnrichDNS:          true,
		EnrichDNSViz:       false,
		EnrichBrands:       false,
		EnrichPricing:      false,
		EnrichMoz:          false,
	}, []providerapi.Provider{
		testProvider{
			source: model.SourceWHOIS,
			raw: &model.RawResponse{
				Source: model.SourceWHOIS,
				Server: "whois.example.test",
				Body:   "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\nName Server: NS1.EXAMPLE.TEST\n",
			},
		},
	}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.deferred = pipeline.New(pipeline.Step{
		NameValue:    "dns",
		EnabledValue: true,
		SupportsFunc: func(result *model.LookupResult) bool {
			return result.Enrichment.DNS == nil
		},
		EnrichFunc: resolver.enrich,
	})

	result, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{
		UseWHOIS:      true,
		LookupLimit:   time.Second,
		ProviderLimit: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Meta.PendingEnrichments) != 1 || result.Meta.PendingEnrichments[0] != "dns" {
		t.Fatalf("pending enrichments: %#v", result.Meta.PendingEnrichments)
	}
	select {
	case <-resolver.started:
		t.Fatal("deferred enrichment ran during fast lookup")
	default:
	}

	done := make(chan *model.LookupResult, 1)
	go func() {
		enriched, _ := service.ApplyDeferred(context.Background(), result)
		done <- enriched
	}()
	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		t.Fatal("deferred enrichment did not start")
	}
	close(resolver.release)
	select {
	case enriched := <-done:
		if len(enriched.Meta.PendingEnrichments) != 0 {
			t.Fatalf("pending after enrich: %#v", enriched.Meta.PendingEnrichments)
		}
		if enriched.Meta.Warnings != nil {
			t.Fatalf("warnings: %#v", enriched.Meta.Warnings)
		}
	case <-time.After(time.Second):
		t.Fatal("deferred enrichment did not finish")
	}
}

func TestOptionalEnrichmentCanBeDisabled(t *testing.T) {
	service := NewService(config.Config{
		LookupTimeout:    time.Second,
		ProviderTimeout:  time.Second,
		RDAPEnabled:      false,
		WHOISEnabled:     true,
		WHOISFollowLimit: 1,
		EnrichEPP:        false,
		EnrichRegistrar:  false,
		EnrichDNS:        false,
		EnrichDNSViz:     false,
		EnrichBrands:     false,
		EnrichPricing:    false,
		EnrichMoz:        false,
	}, []providerapi.Provider{
		testProvider{
			source: model.SourceWHOIS,
			raw: &model.RawResponse{
				Source: model.SourceWHOIS,
				Server: "whois.example.test",
				Body:   "Domain Name: EXAMPLE.TEST\nRegistrar: Cloudflare, Inc.\nRegistrar IANA ID: 1910\nName Server: ivan.ns.cloudflare.com\nStatus: clientTransferProhibited\n",
			},
		},
	}, parsers.NewRegistry(parsers.WHOISParser{}))

	result, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{
		UseWHOIS:      true,
		LookupLimit:   time.Second,
		ProviderLimit: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Statuses[0].Category != "" || result.Statuses[0].Description != "" || result.Statuses[0].URL != "" {
		t.Fatalf("EPP enrichment fields should be empty when disabled: %#v", result.Statuses[0])
	}
	if result.Registrar.URL != "" || result.Registrar.Country != "" || result.Registrar.Brand != nil {
		t.Fatalf("registrar/brand enrichment should be disabled: %#v", result.Registrar)
	}
	if result.Enrichment.DNS != nil || result.Enrichment.DNSViz != nil || result.Enrichment.Pricing != nil || result.Enrichment.Moz != nil {
		t.Fatalf("optional enrichment should be absent: %#v", result.Enrichment)
	}
}

func TestApplyAIIgnoresConfiguredSuffix(t *testing.T) {
	cfg := config.Default()
	cfg.AIEnabled = true
	cfg.AIProvider = "openai-compatible"
	cfg.AIBaseURL = "http://127.0.0.1:1/v1"
	cfg.AIModel = "test-model"
	cfg.AIIgnoreSuffixes = []string{"test"}
	cfg.AIIgnoreRegex = nil
	cfg.EnrichRegistrar = false
	cfg.EnrichBrands = false
	cfg.EnrichPricing = false
	cfg.EnrichMoz = false

	service := NewService(cfg, nil, parsers.NewRegistry())
	result, err := service.ApplyAI(context.Background(), &model.LookupResult{
		NormalizedQuery: "example.test",
		Type:            model.QueryDomain,
		Domain: model.DomainInfo{
			Name:             "example.test",
			Suffix:           "test",
			RegisteredDomain: "example.test",
		},
		Raw: model.RawData{WHOIS: "Domain Name: EXAMPLE.TEST\nRegistrant: Test User\n"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Meta.AI == nil {
		t.Fatal("expected AI trace")
	}
	if result.Meta.AI.Status != "ignored" {
		t.Fatalf("AI status: got %q want ignored", result.Meta.AI.Status)
	}
	if result.Meta.AI.Reason == "" {
		t.Fatal("expected ignore reason")
	}
}

func TestApplyAIIgnoresConfiguredSuffixRegex(t *testing.T) {
	cfg := config.Default()
	cfg.AIEnabled = true
	cfg.AIProvider = "openai-compatible"
	cfg.AIBaseURL = "http://127.0.0.1:1/v1"
	cfg.AIModel = "test-model"
	cfg.AIIgnoreSuffixes = nil
	cfg.AIIgnoreRegex = []string{`^edu\.`}
	cfg.EnrichRegistrar = false
	cfg.EnrichBrands = false
	cfg.EnrichPricing = false
	cfg.EnrichMoz = false

	service := NewService(cfg, nil, parsers.NewRegistry())
	result, err := service.ApplyAI(context.Background(), &model.LookupResult{
		NormalizedQuery: "example.edu.cn",
		Type:            model.QueryDomain,
		Domain: model.DomainInfo{
			Name:             "example.edu.cn",
			Suffix:           "edu.cn",
			RegisteredDomain: "example.edu.cn",
		},
		Raw: model.RawData{WHOIS: "Domain Name: EXAMPLE.EDU.CN\nRegistrant: Test User\n"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Meta.AI == nil || result.Meta.AI.Status != "ignored" || !strings.Contains(result.Meta.AI.Reason, "ai.ignore_regex") {
		t.Fatalf("AI trace: %#v", result.Meta.AI)
	}
}

func (p testProvider) Name() model.SourceName {
	return p.source
}

func (p testProvider) Supports(q model.NormalizedQuery) bool {
	return q.Type == model.QueryDomain
}

func (p testProvider) Lookup(_ context.Context, q model.NormalizedQuery, _ model.LookupOptions) (*model.RawResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	raw := *p.raw
	raw.Query = q.Query
	return &raw, nil
}

func (r *blockingResolver) enrich(_ context.Context, result *model.LookupResult) error {
	close(r.started)
	<-r.release
	result.Enrichment.DNS = &model.DNSInfo{}
	return nil
}

func TestLookupSkipsUnavailableRDAPAndUsesWHOIS(t *testing.T) {
	service := NewService(config.Config{
		LookupTimeout:    time.Second,
		ProviderTimeout:  time.Second,
		RDAPEnabled:      true,
		WHOISEnabled:     true,
		WHOISFollowLimit: 1,
	}, []providerapi.Provider{
		testProvider{
			source: model.SourceRDAP,
			err:    providerapi.Skip(`no RDAP bootstrap server for domain "example.test"`),
		},
		testProvider{
			source: model.SourceWHOIS,
			raw: &model.RawResponse{
				Source: model.SourceWHOIS,
				Server: "whois.example.test",
				Body:   "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\nName Server: NS1.EXAMPLE.TEST\n",
			},
		},
	}, parsers.NewRegistry(parsers.WHOISParser{}))

	result, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{
		UseRDAP:       true,
		UseWHOIS:      true,
		LookupLimit:   time.Second,
		ProviderLimit: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source.Primary != model.SourceWHOIS {
		t.Fatalf("primary source: got %q want whois", result.Source.Primary)
	}
	if len(result.Source.Errors) != 0 {
		t.Fatalf("skipped RDAP should not become source error: %#v", result.Source.Errors)
	}
	var sawSkippedRDAP bool
	for _, trace := range result.Meta.Providers {
		if trace.Source == model.SourceRDAP && trace.Status == "skipped" {
			sawSkippedRDAP = true
		}
	}
	if !sawSkippedRDAP {
		t.Fatalf("expected skipped RDAP trace, got %#v", result.Meta.Providers)
	}
}
