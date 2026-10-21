package lookup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/data/brandmap"
	enrichmentdata "github.com/xmzo/whoice/services/lookup-api/internal/data/enrichment"
	"github.com/xmzo/whoice/services/lookup-api/internal/data/icpsuffixes"
	"github.com/xmzo/whoice/services/lookup-api/internal/data/registrars"
	aienrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/ai"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/brand"
	dnsenrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/dns"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/dnsviz"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/epp"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/fx"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/moz"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pipeline"
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pricing"
	registrarenrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/registrar"
	"github.com/xmzo/whoice/services/lookup-api/internal/merger"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/normalize"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers/delegation"
	"golang.org/x/net/idna"
)

type Service struct {
	cfg              config.Config
	normalizer       normalize.Normalizer
	providers        []providers.Provider
	parsers          *parsers.Registry
	merger           merger.Merger
	registrars       *registrars.Registry
	brands           *brandmap.Registry
	icpSuffixes      *icpsuffixes.List
	enrichment       *enrichmentdata.Registry
	pricing          *pricing.Resolver
	fx               *fx.Service
	enrichers        pipeline.Pipeline
	static           pipeline.Pipeline
	fast             pipeline.Pipeline
	deferred         pipeline.Pipeline
	ai               *aienrich.Enricher
	inflight         *singleflight
	delegation       delegationChecker
	backgroundMu     sync.Mutex
	backgroundCancel context.CancelFunc
}

func NewService(cfg config.Config, providerList []providers.Provider, parserRegistry *parsers.Registry) *Service {
	registrarRegistry, _ := registrars.NewDefaultRegistry(cfg.DataDir)
	brandRegistry, _ := brandmap.NewDefaultRegistry(cfg.DataDir)
	enrichmentRegistry := enrichmentdata.NewDefaultRegistry(cfg.DataDir)
	service := &Service{
		cfg:         cfg,
		normalizer:  normalize.New(cfg.DataDir),
		providers:   providerList,
		parsers:     parserRegistry,
		merger:      merger.New(),
		registrars:  registrarRegistry,
		brands:      brandRegistry,
		icpSuffixes: icpsuffixes.NewDefault(cfg.DataDir).WithExtra(cfg.ICPExtraSuffixes),
		enrichment:  enrichmentRegistry,
		pricing:     buildPricingResolver(cfg),
		fx:          fx.New(cfg.DataDir, cfg.FXCacheTTL),
		ai:          aienrich.New(cfg),
		inflight:    newSingleflight(),
		delegation:  delegation.New(),
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
	return pricing.NewResolver(sources...).WithCache(cfg.DataDir, cfg.PricingCacheTTL)
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

	if opts.OnPartial != nil {
		result, err := s.lookupFresh(ctx, *q, opts, start)
		if result != nil {
			result.Meta.ElapsedMs = time.Since(start).Milliseconds()
		}
		return result, err
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

	providerCtx, stopProviders := context.WithCancel(lookupCtx)
	defer stopProviders()

	var previews *previewer
	var onRaw func(model.RawResponse, []model.ProviderTrace, int)
	if opts.OnPartial != nil {
		previews = &previewer{service: s, ctx: ctx, q: q, opts: opts, start: start}
		onRaw = previews.addRaw
	}

	// The DNS delegation check runs alongside RDAP and WHOIS for every
	// domain: it can show a registration before a slow WHOIS server answers,
	// and it is ready at once when WHOIS and RDAP have nothing.
	var delegated <-chan delegationOutcome
	var stoppedEarly atomic.Bool
	if s.delegationEligible(q, opts) {
		stop := func() {}
		if s.cfg.DNSFirstSuffix(q.Query) {
			stop = func() {
				stoppedEarly.Store(true)
				stopProviders()
			}
		}
		delegated = s.startDelegation(lookupCtx, q, opts, previews, stop)
	}

	rawResponses, sourceErrors, providerTraces := s.runProviders(providerCtx, q, opts, onRaw)
	previews.finish()
	if stoppedEarly.Load() {
		sourceErrors = markStoppedEarly(sourceErrors, providerTraces)
	}
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

	// The delegation result decides only when the sources produced nothing
	// usable; otherwise it is not waited for.
	if delegated != nil && len(parts) == 0 && (stoppedEarly.Load() || whoisUnavailable(providerTraces) || whoisUnreadable(sourceErrors)) {
		if outcome := <-delegated; outcome.trace != nil {
			providerTraces = append(providerTraces, *outcome.trace)
			if outcome.part != nil {
				parts = append(parts, outcome.part)
			}
		}
	}

	if len(parts) == 0 {
		if len(sourceErrors) == 0 {
			// Every source was skipped; report why the DNS fallback failed.
			for _, trace := range providerTraces {
				if trace.Source == model.SourceDNS && trace.Error != "" {
					return nil, fmt.Errorf("no WHOIS or RDAP service for this name, and the DNS delegation check failed: %s", trace.Error)
				}
			}
			return nil, errors.New("no provider returned data")
		}
		return nil, errors.New(sourceErrors[0].Error)
	}

	result := s.merger.Merge(q, parts)
	markClosedSecondLevel(q, result)
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
			Status: "ignored",
			Reason: reason,
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
		// Cached prices and local Moz data cost nothing, so they ship with
		// the first response instead of waiting behind deferred DNS.
		pricing.CachedEnricher{EnabledValue: s.cfg.EnrichPricing, Resolver: s.pricing},
		s.fxStep(false),
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
		s.icpFilingStep(),
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
		// Only suffixes missing from the price cache reach this step; local Moz
		// data is applied by the fast pipeline.
		pricing.NewEnricher(s.cfg.EnrichPricing, s.pricing),
		s.fxStep(true),
	)
}

// fxStep attaches exchange rates to prices. The fast path uses cached rates
// only (refreshing expired ones in the background); the deferred path may
// fetch them.
func (s *Service) fxStep(allowFetch bool) pipeline.Enricher {
	return pipeline.Step{
		NameValue:    "fx",
		EnabledValue: s.cfg.EnrichPricing,
		SupportsFunc: func(result *model.LookupResult) bool {
			return result != nil && result.Enrichment.Pricing != nil && result.Enrichment.Pricing.FX == nil
		},
		EnrichFunc: func(ctx context.Context, result *model.LookupResult) error {
			result.Enrichment.Pricing.FX = s.fx.Snapshot(ctx, pricingCurrencies(result.Enrichment.Pricing), allowFetch)
			return nil
		},
	}
}

func pricingCurrencies(info *model.PricingInfo) []string {
	codes := []string{info.Currency}
	for _, offer := range []*model.PricingOffer{info.RegisterOffer, info.RenewOffer, info.TransferOffer} {
		if offer != nil {
			codes = append(codes, offer.Currency)
		}
	}
	return codes
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
		s.icpFilingStep(),
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

// icpFilingStep marks whether the domain's suffix is on MIIT's list of
// ICP-fileable suffixes. Names under a private suffix (us.kg, github.io) are
// never fileable on their own.
func (s *Service) icpFilingStep() pipeline.Enricher {
	return pipeline.Step{
		NameValue:    "icp_filing",
		EnabledValue: true,
		SupportsFunc: func(result *model.LookupResult) bool {
			return result != nil && result.Type == model.QueryDomain && result.Enrichment.ICPFiling == nil
		},
		EnrichFunc: func(_ context.Context, result *model.LookupResult) error {
			name := result.Domain.RegisteredDomain
			if name == "" {
				name = result.NormalizedQuery
			}
			q, err := s.normalizer.Normalize(name)
			if err != nil || q.Type != model.QueryDomain || q.Suffix == "" {
				return nil
			}
			if !q.PrivateSuffix {
				if matched, ok := s.icpSuffixes.Match(q.Suffix); ok {
					result.Enrichment.ICPFiling = &model.ICPFilingInfo{Eligible: true, Suffix: matched}
					return nil
				}
			}
			suffix, err := idna.Lookup.ToUnicode(q.Suffix)
			if err != nil || suffix == "" {
				suffix = q.Suffix
			}
			result.Enrichment.ICPFiling = &model.ICPFilingInfo{Suffix: suffix}
			return nil
		},
	}
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

// previewer merges the answers received so far and hands them to
// opts.OnPartial while sources are still running. It takes provider answers
// and the parallel DNS delegation result. Only previews that show a
// registration are sent: a "not found" from one source can still be
// contradicted by another, so availability waits for the final result.
type previewer struct {
	service *Service
	ctx     context.Context
	q       model.NormalizedQuery
	opts    model.LookupOptions
	start   time.Time

	mu      sync.Mutex
	parts   []*model.PartialResult
	traces  []model.ProviderTrace
	pending bool
	done    bool
}

func (p *previewer) addRaw(raw model.RawResponse, traces []model.ProviderTrace, pending int) {
	part, err := p.service.parsers.Parse(p.ctx, raw, p.q)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.traces = append([]model.ProviderTrace(nil), traces...)
	p.pending = pending > 0
	if err != nil {
		return
	}
	p.parts = append(p.parts, part)
	if p.pending {
		p.emitLocked(nil)
	}
}

// addDelegation previews a DNS delegation that shows a registration while
// RDAP or WHOIS are still running.
func (p *previewer) addDelegation(part *model.PartialResult, trace *model.ProviderTrace) {
	if p == nil || part == nil || trace == nil || part.Status != model.StatusRegistered {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || (len(p.traces) > 0 && !p.pending) {
		return
	}
	p.parts = append(p.parts, part)
	p.emitLocked(trace)
}

func (p *previewer) finish() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.done = true
	p.mu.Unlock()
}

func (p *previewer) emitLocked(extra *model.ProviderTrace) {
	preview := p.service.merger.Merge(p.q, p.parts)
	if preview.Status != model.StatusRegistered && preview.Status != model.StatusReserved {
		return
	}
	preview.Meta.Providers = append([]model.ProviderTrace(nil), p.traces...)
	if extra != nil {
		preview.Meta.Providers = append(preview.Meta.Providers, *extra)
	}
	preview.Meta.ElapsedMs = time.Since(p.start).Milliseconds()
	p.service.fast.Run(p.ctx, preview)
	p.opts.OnPartial(preview)
}

func (s *Service) runProviders(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions, onRaw func(model.RawResponse, []model.ProviderTrace, int)) ([]model.RawResponse, []model.SourceError, []model.ProviderTrace) {
	type outcome struct {
		raw   *model.RawResponse
		err   error
		src   model.SourceName
		trace model.ProviderTrace
	}

	var wg sync.WaitGroup
	ch := make(chan outcome, len(s.providers))
	started := 0

	for _, provider := range s.providers {
		if !provider.Supports(q) || !s.providerEnabledFor(provider, q, opts) {
			continue
		}
		provider := provider
		started++
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

	go func() {
		wg.Wait()
		close(ch)
	}()

	var raws []model.RawResponse
	var errs []model.SourceError
	var traces []model.ProviderTrace
	for item := range ch {
		traces = append(traces, item.trace)
		if onRaw != nil && item.err == nil && item.raw != nil {
			onRaw(*item.raw, traces, started-len(traces))
		}
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

type requiredProvider interface {
	Required(model.NormalizedQuery) bool
}

// providerEnabledFor also runs WHOIS Web registry modules (the only WHOIS for
// their suffixes) when the WHOIS Web fallback is switched off.
func (s *Service) providerEnabledFor(provider providers.Provider, q model.NormalizedQuery, opts model.LookupOptions) bool {
	if s.providerEnabled(provider.Name(), opts) {
		return true
	}
	required, ok := provider.(requiredProvider)
	return ok && provider.Name() == model.SourceWHOISWeb && opts.UseWHOIS && s.cfg.WHOISEnabled && required.Required(q)
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

type delegationChecker interface {
	Check(ctx context.Context, domain string) (*delegation.Result, error)
}

const (
	delegationTimeout = 5 * time.Second
	// delegationGrace is how long providers may still answer after the
	// parallel delegation check has a result.
	delegationGrace = 500 * time.Millisecond
)

type delegationOutcome struct {
	part  *model.PartialResult
	trace *model.ProviderTrace
}

func (s *Service) delegationEligible(q model.NormalizedQuery, opts model.LookupOptions) bool {
	return s.delegation != nil && q.Type == model.QueryDomain && opts.RDAPServer == "" && opts.WHOISServer == ""
}

// startDelegation runs the delegation check in the background. Once it has a
// result, stop is called after delegationGrace so slow providers no longer
// hold up the lookup.
func (s *Service) startDelegation(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions, previews *previewer, stop func()) <-chan delegationOutcome {
	out := make(chan delegationOutcome, 1)
	go func() {
		part, trace := s.delegationFallback(ctx, q, opts)
		previews.addDelegation(part, trace)
		out <- delegationOutcome{part: part, trace: trace}
		if part == nil {
			return
		}
		timer := time.NewTimer(delegationGrace)
		defer timer.Stop()
		select {
		case <-timer.C:
			stop()
		case <-ctx.Done():
		}
	}()
	return out
}

const stoppedEarlyMessage = "no reply before the DNS delegation check finished"

// markStoppedEarly relabels providers cancelled because the DNS check of a
// lookup.dns_first_suffixes name answered first: their trace becomes
// "stopped" (shown as truncated, not as a failure) and they leave the
// source errors.
func markStoppedEarly(errs []model.SourceError, traces []model.ProviderTrace) []model.SourceError {
	stopped := map[model.SourceName]bool{}
	for i := range traces {
		if traces[i].Status == "error" && isCanceled(traces[i].Error) {
			traces[i].Status = "stopped"
			traces[i].Error = stoppedEarlyMessage
			stopped[traces[i].Source] = true
		}
	}
	kept := errs[:0]
	for _, item := range errs {
		if stopped[item.Source] && isCanceled(item.Error) {
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

// isCanceled matches provider errors caused by context cancellation; net
// errors report it as "operation was canceled" without wrapping the context
// error.
func isCanceled(message string) bool {
	return strings.Contains(message, context.Canceled.Error()) || strings.Contains(message, "operation was canceled")
}

// whoisUnavailable reports whether WHOIS ran and failed, or was skipped
// because the registry has no WHOIS service.
// whoisUnreadable reports a WHOIS reply the parsers rejected (an
// unrecognized or throttled answer).
func whoisUnreadable(errs []model.SourceError) bool {
	for _, item := range errs {
		if item.Source == model.SourceWHOIS {
			return true
		}
	}
	return false
}

func whoisUnavailable(traces []model.ProviderTrace) bool {
	for _, trace := range traces {
		if trace.Source == model.SourceWHOIS && (trace.Status == "error" || trace.Status == "skipped" || trace.Status == "stopped") {
			return true
		}
	}
	return false
}

// delegationFallback infers a domain's status from its DNS delegation when
// WHOIS failed and no other source produced anything, e.g. registries without a public
// WHOIS service (.al) or with an unreachable one (.uy).
func (s *Service) delegationFallback(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) (*model.PartialResult, *model.ProviderTrace) {
	if s.delegation == nil || q.Type != model.QueryDomain || opts.RDAPServer != "" || opts.WHOISServer != "" {
		return nil, nil
	}
	domain := q.RegisteredDomain
	if domain == "" {
		domain = q.Query
	}
	start := time.Now()
	checkCtx, cancel := context.WithTimeout(ctx, delegationTimeout)
	defer cancel()
	trace := &model.ProviderTrace{Source: model.SourceDNS, Status: "ok", Query: domain}
	result, err := s.delegation.Check(checkCtx, domain)
	trace.ElapsedMs = time.Since(start).Milliseconds()
	if err != nil {
		trace.Status = "error"
		trace.Error = err.Error()
		return nil, trace
	}
	trace.Server = result.Server
	trace.Bytes = len(result.Body)
	// In a private wildcard zone (*.github.io) a missing delegation says
	// nothing about whether the name can be had; only registry zones
	// (*.com.ph) delegate every registration.
	if result.Wildcard && q.PrivateSuffix {
		result.Status = model.StatusUnknown
	}
	part := &model.PartialResult{
		Source: model.SourceDNS,
		Status: result.Status,
		Domain: model.DomainInfo{
			Name:             q.Query,
			Suffix:           q.Suffix,
			RegisteredDomain: q.RegisteredDomain,
		},
		Raw:      model.RawData{DNS: result.Body},
		Warnings: []string{fmt.Sprintf("No usable WHOIS or RDAP data; status inferred from the DNS delegation in the %s zone.", result.Zone)},
	}
	for _, host := range result.Nameservers {
		part.Nameservers = append(part.Nameservers, model.Nameserver{Host: host})
	}
	return part, trace
}

// thirdLevelOnlyTLDs accept registrations only under their second-level
// zones (co.zw, com.bd, ...), never directly under the TLD.
var thirdLevelOnlyTLDs = map[string]string{
	"bd": "com.bd", "ck": "co.ck", "er": "com.er", "fk": "co.fk", "jm": "com.jm",
	"kh": "com.kh", "np": "com.np", "pg": "com.pg", "zw": "co.zw",
}

// markClosedSecondLevel reports a missing name directly under such a TLD
// (nic.zw) as not available instead of "available": nobody can register it.
func markClosedSecondLevel(q model.NormalizedQuery, result *model.LookupResult) {
	example, ok := thirdLevelOnlyTLDs[strings.Trim(q.Suffix, ".")]
	if !ok || q.Type != model.QueryDomain || result.Status != model.StatusUnregistered {
		return
	}
	result.Status = model.StatusReserved
	result.Domain.Reserved = true
	result.Meta.Warnings = append(result.Meta.Warnings, fmt.Sprintf(
		"The .%s registry only accepts registrations under second-level zones such as %s; names directly under .%s cannot be registered.",
		q.Suffix, example, q.Suffix))
}
