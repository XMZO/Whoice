package lookup

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pipeline"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pricing"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	providerapi "github.com/xmzo/whoice/services/lookup-api/internal/providers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers/delegation"
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
	want := []string{"epp", "dns", "dnsviz", "registrar", "brand", "icp_filing", "for_sale", "pricing", "moz"}
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

type fakeDelegation struct {
	result *delegation.Result
	err    error
	calls  int
}

func (f *fakeDelegation) Check(_ context.Context, domain string) (*delegation.Result, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	result := *f.result
	result.Domain = domain
	return &result, nil
}

func delegationTestService(checker delegationChecker, whoisErr error) *Service {
	service := NewService(config.Config{
		LookupTimeout:   time.Second,
		ProviderTimeout: time.Second,
		RDAPEnabled:     true,
		WHOISEnabled:    true,
	}, []providerapi.Provider{
		testProvider{source: model.SourceRDAP, err: providerapi.Skip(`no RDAP bootstrap server for domain "ka.uy"`)},
		testProvider{source: model.SourceWHOIS, err: whoisErr},
	}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.delegation = checker
	return service
}

func TestLookupFallsBackToDNSDelegationWhenRegistryHasNoWHOIS(t *testing.T) {
	checker := &fakeDelegation{result: &delegation.Result{
		Zone:        "uy",
		Server:      "a.nic.uy (200.40.30.254)",
		Status:      model.StatusRegistered,
		Nameservers: []string{"jeff.ns.cloudflare.com", "sloan.ns.cloudflare.com"},
		Body:        "; DNS delegation check for ka.uy\n",
	}}
	service := delegationTestService(checker, errors.New("dial tcp 164.73.128.51:43: i/o timeout"))
	result, err := service.Lookup(context.Background(), "ka.uy", model.LookupOptions{UseRDAP: true, UseWHOIS: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusRegistered || result.Source.Primary != model.SourceDNS || !result.Domain.Registered {
		t.Fatalf("status %q primary %q", result.Status, result.Source.Primary)
	}
	if len(result.Nameservers) != 2 || result.Raw.DNS == "" {
		t.Fatalf("nameservers %#v raw %q", result.Nameservers, result.Raw.DNS)
	}
	if len(result.Source.Errors) != 1 || result.Source.Errors[0].Source != model.SourceWHOIS {
		t.Fatalf("WHOIS failure should stay visible: %#v", result.Source.Errors)
	}
	var trace *model.ProviderTrace
	for i := range result.Meta.Providers {
		if result.Meta.Providers[i].Source == model.SourceDNS {
			trace = &result.Meta.Providers[i]
		}
	}
	if trace == nil || trace.Status != "ok" || trace.Server != "a.nic.uy (200.40.30.254)" {
		t.Fatalf("dns trace: %#v", result.Meta.Providers)
	}
	if len(result.Meta.Warnings) == 0 || !strings.Contains(result.Meta.Warnings[0], "DNS delegation") {
		t.Fatalf("warnings: %#v", result.Meta.Warnings)
	}
}

func TestLookupDNSDelegationReportsUnregistered(t *testing.T) {
	checker := &fakeDelegation{result: &delegation.Result{Zone: "al", Status: model.StatusUnregistered, Body: "; NXDOMAIN\n"}}
	service := delegationTestService(checker, providerapi.Skip("the registry for .al publishes no WHOIS service"))
	result, err := service.Lookup(context.Background(), "free-name.al", model.LookupOptions{UseRDAP: true, UseWHOIS: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusUnregistered || result.Domain.Registered {
		t.Fatalf("status %q", result.Status)
	}
}

func TestLookupKeepsProviderErrorWhenDelegationFails(t *testing.T) {
	checker := &fakeDelegation{err: errors.New("no nameservers found")}
	service := delegationTestService(checker, errors.New("dial tcp 164.73.128.51:43: i/o timeout"))
	_, err := service.Lookup(context.Background(), "ka.uy", model.LookupOptions{UseRDAP: true, UseWHOIS: true})
	if err == nil || !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupSkipsDelegationForCustomServers(t *testing.T) {
	checker := &fakeDelegation{err: errors.New("unexpected")}
	service := delegationTestService(checker, errors.New("dial tcp 192.0.2.1:43: i/o timeout"))
	_, _ = service.Lookup(context.Background(), "ka.uy", model.LookupOptions{UseRDAP: true, UseWHOIS: true, WHOISServer: "192.0.2.1"})
	if checker.calls != 0 {
		t.Fatal("custom server lookups must not fall back to DNS")
	}
}

type hangingProvider struct{ source model.SourceName }

func (p hangingProvider) Name() model.SourceName                { return p.source }
func (p hangingProvider) Supports(q model.NormalizedQuery) bool { return q.Type == model.QueryDomain }
func (p hangingProvider) Lookup(ctx context.Context, _ model.NormalizedQuery, _ model.LookupOptions) (*model.RawResponse, error) {
	<-ctx.Done()
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("operation was canceled")}
}

func TestDelegationFirstTLDDoesNotWaitForWHOISTimeout(t *testing.T) {
	checker := &fakeDelegation{result: &delegation.Result{
		Zone: "uy", Server: "a.nic.uy (200.40.30.254)", Status: model.StatusRegistered,
		Nameservers: []string{"jeff.ns.cloudflare.com"}, Body: "; delegated\n",
	}}
	service := NewService(config.Config{LookupTimeout: 20 * time.Second, ProviderTimeout: 10 * time.Second, WHOISEnabled: true, DNSFirstSuffixes: []string{"uy"}},
		[]providerapi.Provider{hangingProvider{source: model.SourceWHOIS}}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.delegation = checker

	start := time.Now()
	result, err := service.Lookup(context.Background(), "ka.uy", model.LookupOptions{UseWHOIS: true})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > delegationGrace+2*time.Second {
		t.Fatalf("lookup waited %s for a hanging WHOIS server", elapsed)
	}
	if result.Status != model.StatusRegistered || result.Source.Primary != model.SourceDNS {
		t.Fatalf("status %q primary %q", result.Status, result.Source.Primary)
	}
	if len(result.Source.Errors) != 0 {
		t.Fatalf("a truncated WHOIS is not a source error: %#v", result.Source.Errors)
	}
	if len(result.Meta.Providers) == 0 || result.Meta.Providers[0].Status != "stopped" || result.Meta.Providers[0].Error != stoppedEarlyMessage {
		t.Fatalf("WHOIS trace should be marked stopped: %#v", result.Meta.Providers)
	}
}

func TestDelegationFirstPrefersWHOISWhenItAnswers(t *testing.T) {
	checker := &fakeDelegation{result: &delegation.Result{Zone: "uy", Status: model.StatusRegistered, Body: "; delegated\n"}}
	service := NewService(config.Config{LookupTimeout: 5 * time.Second, ProviderTimeout: 5 * time.Second, WHOISEnabled: true, DNSFirstSuffixes: []string{"uy"}},
		[]providerapi.Provider{testProvider{source: model.SourceWHOIS, raw: &model.RawResponse{
			Source: model.SourceWHOIS, Server: "whois.nic.org.uy",
			Body: "Domain Name: KA.UY\nRegistrar: Example Registrar\nName Server: NS1.EXAMPLE.UY\n",
		}}}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.delegation = checker

	result, err := service.Lookup(context.Background(), "ka.uy", model.LookupOptions{UseWHOIS: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source.Primary != model.SourceWHOIS || result.Raw.DNS != "" {
		t.Fatalf("primary %q raw dns %q", result.Source.Primary, result.Raw.DNS)
	}
}

type delayedProvider struct {
	testProvider
	delay time.Duration
}

func (p delayedProvider) Lookup(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) (*model.RawResponse, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return p.testProvider.Lookup(ctx, q, opts)
}

func TestLookupEmitsRegisteredPreviewBeforeSlowProvider(t *testing.T) {
	service := NewService(config.Config{LookupTimeout: 5 * time.Second, ProviderTimeout: 5 * time.Second, RDAPEnabled: true, WHOISEnabled: true},
		[]providerapi.Provider{
			testProvider{source: model.SourceWHOIS, raw: &model.RawResponse{
				Source: model.SourceWHOIS, Server: "whois.example.test",
				Body: "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\nName Server: NS1.EXAMPLE.TEST\n",
			}},
			delayedProvider{testProvider: testProvider{source: model.SourceRDAP, err: errors.New("rdap timeout")}, delay: 200 * time.Millisecond},
		}, parsers.NewRegistry(parsers.WHOISParser{}))

	var previews []*model.LookupResult
	result, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{
		UseRDAP: true, UseWHOIS: true,
		OnPartial: func(preview *model.LookupResult) { previews = append(previews, preview) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(previews) != 1 {
		t.Fatalf("previews: %d", len(previews))
	}
	if previews[0].Status != model.StatusRegistered || previews[0].Registrar.Name != "Example Registrar" || len(previews[0].Meta.Providers) != 1 {
		t.Fatalf("preview: %#v", previews[0])
	}
	if len(result.Meta.Providers) != 2 || len(result.Source.Errors) != 1 {
		t.Fatalf("final providers %#v errors %#v", result.Meta.Providers, result.Source.Errors)
	}
}

func TestLookupDoesNotPreviewAvailability(t *testing.T) {
	service := NewService(config.Config{LookupTimeout: 5 * time.Second, ProviderTimeout: 5 * time.Second, RDAPEnabled: true, WHOISEnabled: true},
		[]providerapi.Provider{
			testProvider{source: model.SourceWHOIS, raw: &model.RawResponse{Source: model.SourceWHOIS, Server: "whois.example.test", Body: "No match for \"FREE.TEST\".\n"}},
			delayedProvider{testProvider: testProvider{source: model.SourceRDAP, err: errors.New("rdap timeout")}, delay: 100 * time.Millisecond},
		}, parsers.NewRegistry(parsers.WHOISParser{}))

	calls := 0
	result, err := service.Lookup(context.Background(), "free.test", model.LookupOptions{
		UseRDAP: true, UseWHOIS: true,
		OnPartial: func(*model.LookupResult) { calls++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("availability must wait for the final result, got %d previews (final status %q)", calls, result.Status)
	}
}

type registryWebProvider struct {
	testProvider
	required bool
}

func (p registryWebProvider) Required(model.NormalizedQuery) bool { return p.required }

func TestRegistryWHOISWebRunsWithFallbackSwitchedOff(t *testing.T) {
	for _, required := range []bool{true, false} {
		web := registryWebProvider{required: required, testProvider: testProvider{source: model.SourceWHOISWeb, raw: &model.RawResponse{
			Source: model.SourceWHOISWeb, Server: "https://www.dnshe.com/whois.php",
			Body: "Domain Name: anby.cc.cd\nRegistrar: DNSHE\nName Server: renan.ns.cloudflare.com\n",
		}}}
		service := NewService(config.Config{LookupTimeout: time.Second, ProviderTimeout: time.Second, WHOISEnabled: true, WHOISWebEnabled: false},
			[]providerapi.Provider{web}, parsers.NewRegistry(parsers.WHOISParser{}))
		service.delegation = &fakeDelegation{err: errors.New("unused")}
		result, err := service.Lookup(context.Background(), "anby.cc.cd", model.LookupOptions{UseWHOIS: true})
		if required && (err != nil || result.Source.Primary != model.SourceWHOISWeb) {
			t.Fatalf("registry module should run: %v %#v", err, result)
		}
		if !required && err == nil {
			t.Fatalf("plain WHOIS Web modules stay off: %#v", result.Source)
		}
	}
}

type staticPriceSource struct{ prices map[string]float64 }

func (s staticPriceSource) Name() string { return "static" }

func (s staticPriceSource) Lookup(_ context.Context, suffix string) (model.PricingInfo, bool, error) {
	price, ok := s.prices[suffix]
	if !ok {
		return model.PricingInfo{}, false, nil
	}
	return model.PricingInfo{Register: &price, Currency: "USD"}, true, nil
}

func TestCachedPricingShipsWithTheFirstResponse(t *testing.T) {
	service := NewService(config.Config{
		LookupTimeout: time.Second, ProviderTimeout: time.Second, WHOISEnabled: true,
		LookupFastResponse: true, EnrichDNS: true, EnrichPricing: true,
	}, []providerapi.Provider{
		testProvider{source: model.SourceWHOIS, raw: &model.RawResponse{
			Source: model.SourceWHOIS, Server: "whois.example",
			Body: "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\n",
		}},
	}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.pricing = pricing.NewResolver(staticPriceSource{prices: map[string]float64{"test": 9}}).WithCache(t.TempDir(), time.Hour)
	service.fast = service.buildFastPipeline()
	service.deferred = service.buildDeferredPipeline()

	lookupOnce := func(query string) *model.LookupResult {
		result, err := service.Lookup(context.Background(), query, model.LookupOptions{UseWHOIS: true})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	has := func(names []string, want string) bool {
		for _, name := range names {
			if name == want {
				return true
			}
		}
		return false
	}

	// Cache miss: pricing is deferred.
	first := lookupOnce("example.test")
	if first.Enrichment.Pricing != nil || !has(first.Meta.PendingEnrichments, "pricing") {
		t.Fatalf("cache miss should defer pricing: %#v %v", first.Enrichment.Pricing, first.Meta.PendingEnrichments)
	}
	if _, err := service.ApplyDeferred(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	// Cache hit: prices arrive with the lookup itself.
	second := lookupOnce("example.test")
	if second.Enrichment.Pricing == nil || second.Enrichment.Pricing.CachedAt == "" || has(second.Meta.PendingEnrichments, "pricing") {
		t.Fatalf("cached prices should ship immediately: %#v %v", second.Enrichment.Pricing, second.Meta.PendingEnrichments)
	}
	if !has(second.Meta.PendingEnrichments, "dns") {
		t.Fatalf("DNS stays deferred: %v", second.Meta.PendingEnrichments)
	}
}

func TestMissingNameDirectlyUnderThirdLevelOnlyTLDIsNotAvailable(t *testing.T) {
	for query, want := range map[string]model.ResultStatus{
		"nic.zw":          model.StatusReserved,
		"free.co.zw":      model.StatusUnregistered,
		"free.example.zz": model.StatusUnregistered,
	} {
		q := model.NormalizedQuery{Type: model.QueryDomain, Query: query, Suffix: suffixFromDomain(query)}
		if query == "nic.zw" {
			q.Suffix = "zw"
		}
		result := &model.LookupResult{Type: model.QueryDomain, Status: model.StatusUnregistered}
		markClosedSecondLevel(q, result)
		if result.Status != want {
			t.Fatalf("%s: status %q want %q", query, result.Status, want)
		}
	}
	registered := &model.LookupResult{Type: model.QueryDomain, Status: model.StatusRegistered}
	markClosedSecondLevel(model.NormalizedQuery{Type: model.QueryDomain, Query: "x.zw", Suffix: "zw"}, registered)
	if registered.Status != model.StatusRegistered {
		t.Fatal("existing names stay registered")
	}
}

type slowDelegation struct {
	delay  time.Duration
	result *delegation.Result
}

func (s slowDelegation) Check(ctx context.Context, domain string) (*delegation.Result, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	result := *s.result
	result.Domain = domain
	return &result, nil
}

func TestDNSDelegationPreviewsBeforeSlowWHOIS(t *testing.T) {
	whois := delayedProvider{delay: 300 * time.Millisecond, testProvider: testProvider{source: model.SourceWHOIS, raw: &model.RawResponse{
		Source: model.SourceWHOIS, Server: "whois.example",
		Body: "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\nName Server: NS1.EXAMPLE.TEST\n",
	}}}
	service := NewService(config.Config{LookupTimeout: 5 * time.Second, ProviderTimeout: 5 * time.Second, WHOISEnabled: true},
		[]providerapi.Provider{whois}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.delegation = slowDelegation{delay: 10 * time.Millisecond, result: &delegation.Result{
		Zone: "test", Status: model.StatusRegistered, Nameservers: []string{"ns1.example.test"}, Body: "; delegated\n",
	}}

	var previews []*model.LookupResult
	result, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{
		UseWHOIS: true, OnPartial: func(p *model.LookupResult) { previews = append(previews, p) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(previews) != 1 || previews[0].Status != model.StatusRegistered || previews[0].Source.Primary != model.SourceDNS {
		t.Fatalf("expected one DNS preview, got %d: %#v", len(previews), previews)
	}
	if result.Source.Primary != model.SourceWHOIS || result.Registrar.Name != "Example Registrar" || result.Raw.DNS != "" {
		t.Fatalf("final result should come from WHOIS: %#v", result.Source)
	}
}

func TestLookupDoesNotWaitForSlowDNSWhenWHOISAnswers(t *testing.T) {
	service := NewService(config.Config{LookupTimeout: 5 * time.Second, ProviderTimeout: 5 * time.Second, WHOISEnabled: true},
		[]providerapi.Provider{testProvider{source: model.SourceWHOIS, raw: &model.RawResponse{
			Source: model.SourceWHOIS, Server: "whois.example", Body: "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\n",
		}}}, parsers.NewRegistry(parsers.WHOISParser{}))
	service.delegation = slowDelegation{delay: 3 * time.Second, result: &delegation.Result{Zone: "test", Status: model.StatusRegistered}}
	start := time.Now()
	if _, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{UseWHOIS: true}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("lookup waited %s for the DNS check", elapsed)
	}
}

func TestWildcardVerdictOnlyForRegistryZones(t *testing.T) {
	for _, private := range []bool{false, true} {
		checker := &fakeDelegation{result: &delegation.Result{Zone: "github.io", Status: model.StatusUnregistered, Wildcard: true, Body: "; wildcard\n"}}
		service := delegationTestService(checker, providerapi.Skip("no WHOIS server for names under github.io"))
		q := model.NormalizedQuery{Type: model.QueryDomain, Query: "foo.github.io", Suffix: "github.io", RegisteredDomain: "foo.github.io", PrivateSuffix: private}
		part, _ := service.delegationFallback(context.Background(), q, model.LookupOptions{})
		want := model.StatusUnregistered
		if private {
			want = model.StatusUnknown
		}
		if part == nil || part.Status != want {
			t.Fatalf("private=%v: %#v", private, part)
		}
	}
}
