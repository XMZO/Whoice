package lookup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/data/brandmap"
	enrichmentdata "github.com/xmzo/whoice/services/lookup-api/internal/data/enrichment"
	"github.com/xmzo/whoice/services/lookup-api/internal/data/registrars"
	aienrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/ai"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/brand"
	dnsenrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/dns"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/dnsviz"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/epp"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/moz"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pipeline"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pricing"
	registrarenrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/registrar"
	"github.com/xmzo/whoice/services/lookup-api/internal/merger"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/normalize"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

type Service struct {
	cfg              config.Config
	normalizer       normalize.Normalizer
	providers        []providers.Provider
	parsers          *parsers.Registry
	merger           merger.Merger
	registrars       *registrars.Registry
	brands           *brandmap.Registry
	enrichment       *enrichmentdata.Registry
	pricing          *pricing.Resolver
	enrichers        pipeline.Pipeline
	static           pipeline.Pipeline
	fast             pipeline.Pipeline
	deferred         pipeline.Pipeline
	ai               *aienrich.Enricher
	inflight         *singleflight
	backgroundMu     sync.Mutex
	backgroundCancel context.CancelFunc
}

func NewService(cfg config.Config, providerList []providers.Provider, parserRegistry *parsers.Registry) *Service {
	registrarRegistry, _ := registrars.NewDefaultRegistry(cfg.DataDir)
	brandRegistry, _ := brandmap.NewDefaultRegistry(cfg.DataDir)
	enrichmentRegistry := enrichmentdata.NewDefaultRegistry(cfg.DataDir)
	service := &Service{
		cfg:        cfg,
		normalizer: normalize.New(cfg.DataDir),
		providers:  providerList,
		parsers:    parserRegistry,
		merger:     merger.New(),
		registrars: registrarRegistry,
		brands:     brandRegistry,
		enrichment: enrichmentRegistry,
		pricing:    buildPricingResolver(cfg),
		ai:         aienrich.New(cfg),
		inflight:   newSingleflight(),
	}
	service.enrichers = service.buildPipeline()
	service.static = service.buildStaticPipeline()
	service.fast = service.buildFastPipeline()
	service.deferred = service.buildDeferredPipeline()
	return service
}

func buildPricingResolver(cfg config.Config) *pricing.Resolver {
	sources := []pricing.Source{pricing.NewLocalSnapshotSource(cfg.DataDir)}
	if cfg.EnrichPricing {
		sources = append([]pricing.Source{pricing.NewMiqingjuSnapshotSource()}, sources...)
	}
	return pricing.NewResolver(sources...)
}

func (s *Service) StartBackground(ctx context.Context) {
	if s == nil || s.pricing == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.backgroundMu.Lock()
	defer s.backgroundMu.Unlock()
	if s.backgroundCancel != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.backgroundCancel = cancel
	s.pricing.Start(runCtx)
}

func (s *Service) StopBackground() {
	if s == nil {
		return
	}
	s.backgroundMu.Lock()
	defer s.backgroundMu.Unlock()
	if s.backgroundCancel != nil {
		s.backgroundCancel()
		s.backgroundCancel = nil
	}
}

func (s *Service) Lookup(ctx context.Context, input string, opts model.LookupOptions) (*model.LookupResult, error) {
	start := time.Now()
	q, err := s.normalizer.NormalizeWithOptions(input, opts)
	if err != nil {
		return nil, err
	}

	if opts.LookupLimit <= 0 {
		opts.LookupLimit = s.cfg.LookupTimeout
	}
	if opts.ProviderLimit <= 0 {
		opts.ProviderLimit = s.cfg.ProviderTimeout
	}
	if opts.WHOISFollow < 0 {
		opts.WHOISFollow = s.cfg.WHOISFollowLimit
	}
	if !opts.FastResponseSet {
		opts.FastResponse = s.cfg.LookupFastResponse
	}
	if !opts.UseRDAP && !opts.UseWHOIS {
		opts.UseRDAP = true
		opts.UseWHOIS = true
	}

	key := requestKey(*q, opts)
	return s.inflight.Do(ctx, key, func(ctx context.Context) (*model.LookupResult, error) {
		result, err := s.lookupFresh(ctx, *q, opts, start)
		if result != nil {
			result.Meta.ElapsedMs = time.Since(start).Milliseconds()
		}
		return result, err
	})
}

func (s *Service) lookupFresh(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions, start time.Time) (*model.LookupResult, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, opts.LookupLimit)
	defer cancel()

	rawResponses, sourceErrors, providerTraces := s.runProviders(lookupCtx, q, opts)
	parts := make([]*model.PartialResult, 0, len(rawResponses))
	for _, raw := range rawResponses {
		part, err := s.parsers.Parse(ctx, raw, q)
		if err != nil {
			sourceErrors = append(sourceErrors, model.SourceError{
				Source: raw.Source,
				Server: raw.Server,
				Error:  err.Error(),
			})
			continue
		}
		parts = append(parts, part)
	}

	if len(parts) == 0 {
		if len(sourceErrors) == 0 {
			return nil, errors.New("no provider returned data")
		}
		return nil, errors.New(sourceErrors[0].Error)
	}

	result := s.merger.Merge(q, parts)
	result.Source.Errors = sourceErrors
	result.Meta.Providers = providerTraces
	result.Meta.ElapsedMs = time.Since(start).Milliseconds()

	if opts.FastResponse {
		s.fast.Run(ctx, result)
		result.Meta.PendingEnrichments = s.deferred.PendingNames(result)
	} else {
		s.enrichers.Run(ctx, result)
	}

	return result, nil
}

func (s *Service) ApplyDeferred(ctx context.Context, result *model.LookupResult) (*model.LookupResult, error) {
	if result == nil {
		return nil, errors.New("lookup result is required")
	}
	result = cloneResult(result)
	if len(result.Meta.PendingEnrichments) == 0 && hasDeferredEnrichment(result) {
		return result, nil
	}
	result.Meta.PendingEnrichments = nil
	s.deferred.Run(ctx, result)
	result.Meta.PendingEnrichments = nil
	return result, nil
}

func (s *Service) ApplyAI(ctx context.Context, result *model.LookupResult, force bool) (*model.LookupResult, error) {
	if result == nil {
		return nil, errors.New("lookup result is required")
	}
	result = cloneResult(result)
	if s.ai == nil || !s.ai.Enabled() {
		trace := model.AITrace{Status: "skipped"}
		result.Meta.AI = &trace
		return result, nil
	}
	if reason := s.aiIgnoreReason(result); reason != "" {
		trace := model.AITrace{
			Provider: s.cfg.AIProvider,
			Model:    s.cfg.AIModel,
			Status:   "ignored",
			Reason:   reason,
		}
		result.Meta.AI = &trace
		s.static.Run(ctx, result)
		return result, nil
	}
	trace := s.ai.Apply(ctx, result, force)
	result.Meta.AI = &trace
	if trace.Status == "error" && trace.Error != "" {
		result.Meta.Warnings = append(result.Meta.Warnings, "AI registration analysis failed: "+trace.Error)
	}
	s.static.Run(ctx, result)
	return result, nil
}

func (s *Service) aiIgnoreReason(result *model.LookupResult) string {
	if result == nil || result.Type != model.QueryDomain {
		return ""
	}
	for _, suffix := range aiCandidateSuffixes(result) {
		if reason := s.cfg.AIIgnoreReasonForSuffix(suffix); reason != "" {
			return reason
		}
	}
	return ""
}

func aiCandidateSuffixes(result *model.LookupResult) []string {
	candidates := []string{
		result.Domain.Suffix,
		suffixFromDomain(result.Domain.RegisteredDomain),
		suffixFromDomain(result.Domain.Name),
		suffixFromDomain(result.NormalizedQuery),
	}
	seen := map[string]bool{}
	var suffixes []string
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.Trim(strings.TrimSpace(candidate), "."))
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		suffixes = append(suffixes, candidate)
	}
	return suffixes
}

func suffixFromDomain(domain string) string {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if domain == "" {
		return ""
	}
	if index := strings.Index(domain, "."); index >= 0 && index < len(domain)-1 {
		return domain[index+1:]
	}
	return domain
}

func (s *Service) buildPipeline() pipeline.Pipeline {
	enrichers := []pipeline.Enricher{
		pipeline.Step{
			NameValue:    "epp",
			EnabledValue: s.cfg.EnrichEPP,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && len(result.Statuses) > 0
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				epp.Apply(result)
				return nil
			},
		},
		pipeline.Step{
			NameValue:    "dns",
			EnabledValue: s.cfg.EnrichDNS,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain && result.NormalizedQuery != ""
			},
			TimeoutValue: s.cfg.DNSTimeout,
			EnrichFunc: func(ctx context.Context, result *model.LookupResult) error {
				dnsenrich.ApplyWithOptions(ctx, result, dnsenrich.Options{
					Timeout:      s.cfg.DNSTimeout,
					Servers:      s.cfg.DNSServers(),
					DoHServers:   s.cfg.DNSDoHResolvers,
					FilterFakeIP: s.cfg.DNSFilterFakeIP,
				})
				return nil
			},
		},
		pipeline.Step{
			NameValue:    "dnsviz",
			EnabledValue: s.cfg.EnrichDNSViz,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				dnsviz.Apply(result)
				return nil
			},
		},
	}
	enrichers = append(enrichers, s.staticEnrichers()...)
	return pipeline.New(enrichers...)
}

func (s *Service) buildFastPipeline() pipeline.Pipeline {
	return pipeline.New(append([]pipeline.Enricher{
		pipeline.Step{
			NameValue:    "epp",
			EnabledValue: s.cfg.EnrichEPP,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && len(result.Statuses) > 0
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				epp.Apply(result)
				return nil
			},
		},
		pipeline.Step{
			NameValue:    "dnsviz",
			EnabledValue: s.cfg.EnrichDNSViz,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				dnsviz.Apply(result)
				return nil
			},
		},
		pipeline.Step{
			NameValue:    "registrar",
			EnabledValue: s.cfg.EnrichRegistrar,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				registrarenrich.Apply(result, s.registrars)
				return nil
			},
		},
	}, s.brandEnrichers()...)...)
}

func (s *Service) buildDeferredPipeline() pipeline.Pipeline {
	return pipeline.New(
		pipeline.Step{
			NameValue:    "dns",
			EnabledValue: s.cfg.EnrichDNS,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain && result.NormalizedQuery != "" && result.Enrichment.DNS == nil
			},
			TimeoutValue: s.cfg.DNSTimeout,
			EnrichFunc: func(ctx context.Context, result *model.LookupResult) error {
				dnsenrich.ApplyWithOptions(ctx, result, dnsenrich.Options{
					Timeout:      s.cfg.DNSTimeout,
					Servers:      s.cfg.DNSServers(),
					DoHServers:   s.cfg.DNSDoHResolvers,
					FilterFakeIP: s.cfg.DNSFilterFakeIP,
				})
				return nil
			},
		},
		pricing.NewEnricher(s.cfg.EnrichPricing, s.pricing),
		pipeline.Step{
			NameValue:    "moz",
			EnabledValue: s.cfg.EnrichMoz,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain && result.Enrichment.Moz == nil
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				moz.Apply(result, s.enrichment)
				return nil
			},
		},
	)
}

func (s *Service) buildStaticPipeline() pipeline.Pipeline {
	return pipeline.New(s.staticEnrichers()...)
}

func (s *Service) staticEnrichers() []pipeline.Enricher {
	enrichers := []pipeline.Enricher{
		pipeline.Step{
			NameValue:    "registrar",
			EnabledValue: s.cfg.EnrichRegistrar,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				registrarenrich.Apply(result, s.registrars)
				return nil
			},
		},
	}
	enrichers = append(enrichers, s.brandEnrichers()...)
	enrichers = append(enrichers,
		pricing.NewEnricher(s.cfg.EnrichPricing, s.pricing),
		pipeline.Step{
			NameValue:    "moz",
			EnabledValue: s.cfg.EnrichMoz,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				moz.Apply(result, s.enrichment)
				return nil
			},
		},
	)
	return enrichers
}

func (s *Service) brandEnrichers() []pipeline.Enricher {
	return []pipeline.Enricher{
		pipeline.Step{
			NameValue:    "brand",
			EnabledValue: s.cfg.EnrichBrands,
			SupportsFunc: func(result *model.LookupResult) bool {
				return result != nil && result.Type == model.QueryDomain
			},
			EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
				brand.Apply(result, s.brands)
				return nil
			},
		},
	}
}

func hasDeferredEnrichment(result *model.LookupResult) bool {
	if result == nil {
		return false
	}
	return result.Enrichment.DNS != nil || result.Enrichment.Pricing != nil || result.Enrichment.Moz != nil
}

func (s *Service) runProviders(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) ([]model.RawResponse, []model.SourceError, []model.ProviderTrace) {
	type outcome struct {
		raw   *model.RawResponse
		err   error
		src   model.SourceName
		trace model.ProviderTrace
	}

	var wg sync.WaitGroup
	ch := make(chan outcome, len(s.providers))

	for _, provider := range s.providers {
		if !provider.Supports(q) || !s.providerEnabled(provider.Name(), opts) {
			continue
		}
		provider := provider
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			providerCtx, cancel := context.WithTimeout(ctx, opts.ProviderLimit)
			defer cancel()
			raw, err := provider.Lookup(providerCtx, q, opts)
			trace := model.ProviderTrace{
				Source:    provider.Name(),
				Status:    "ok",
				ElapsedMs: time.Since(start).Milliseconds(),
			}
			if raw != nil {
				trace.Server = raw.Server
				trace.Query = raw.Query
				trace.StatusCode = raw.StatusCode
				trace.ContentType = raw.ContentType
				trace.Bytes = len(raw.Body)
				if raw.ElapsedMs > 0 {
					trace.ElapsedMs = raw.ElapsedMs
				}
			}
			if err != nil {
				trace.Status = "error"
				trace.Error = err.Error()
				if providers.IsSkip(err) {
					trace.Status = "skipped"
				}
			}
			ch <- outcome{raw: raw, err: err, src: provider.Name(), trace: trace}
		}()
	}

	wg.Wait()
	close(ch)

	var raws []model.RawResponse
	var errs []model.SourceError
	var traces []model.ProviderTrace
	for item := range ch {
		traces = append(traces, item.trace)
		if item.err != nil {
			if providers.IsSkip(item.err) {
				continue
			}
			errs = append(errs, model.SourceError{Source: item.src, Error: item.err.Error()})
			continue
		}
		if item.raw != nil {
			raws = append(raws, *item.raw)
		}
	}

	return raws, errs, traces
}

func (s *Service) providerEnabled(source model.SourceName, opts model.LookupOptions) bool {
	switch source {
	case model.SourceRDAP:
		return s.cfg.RDAPEnabled && opts.UseRDAP
	case model.SourceWHOIS:
		return s.cfg.WHOISEnabled && opts.UseWHOIS
	case model.SourceWHOISWeb:
		return s.cfg.WHOISWebEnabled && opts.UseWHOIS
	default:
		return false
	}
}

func requestKey(q model.NormalizedQuery, opts model.LookupOptions) string {
	return fmt.Sprintf("%s:%s:rdap=%t:whois=%t:rs=%s:ws=%s:wf=%d:exact=%t:fast=%t", q.Type, q.Query, opts.UseRDAP, opts.UseWHOIS, opts.RDAPServer, opts.WHOISServer, opts.WHOISFollow, opts.ExactDomain, opts.FastResponse)
}
