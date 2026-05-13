package lookup

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/xmzo/whoice/services/lookup-api/internal/enrich/pricing"
	registrarenrich "github.com/xmzo/whoice/services/lookup-api/internal/enrich/registrar"
	"github.com/xmzo/whoice/services/lookup-api/internal/merger"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/normalize"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

type Service struct {
	cfg        config.Config
	normalizer normalize.Normalizer
	providers  []providers.Provider
	parsers    *parsers.Registry
	merger     merger.Merger
	registrars *registrars.Registry
	brands     *brandmap.Registry
	enrichment *enrichmentdata.Registry
	ai         *aienrich.Enricher
	inflight   *singleflight
}

func NewService(cfg config.Config, providerList []providers.Provider, parserRegistry *parsers.Registry) *Service {
	registrarRegistry, _ := registrars.NewDefaultRegistry(cfg.DataDir)
	brandRegistry, _ := brandmap.NewDefaultRegistry(cfg.DataDir)
	enrichmentRegistry := enrichmentdata.NewDefaultRegistry(cfg.DataDir)
	return &Service{
		cfg:        cfg,
		normalizer: normalize.New(cfg.DataDir),
		providers:  providerList,
		parsers:    parserRegistry,
		merger:     merger.New(),
		registrars: registrarRegistry,
		brands:     brandRegistry,
		enrichment: enrichmentRegistry,
		ai:         aienrich.New(cfg),
		inflight:   newSingleflight(),
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

	if s.cfg.EnrichEPP {
		epp.Apply(result)
	}
	if s.cfg.EnrichDNS {
		dnsenrich.ApplyWithOptions(ctx, result, dnsenrich.Options{
			Timeout:      s.cfg.DNSTimeout,
			Servers:      s.cfg.DNSServers(),
			DoHServers:   s.cfg.DNSDoHResolvers,
			FilterFakeIP: s.cfg.DNSFilterFakeIP,
		})
	}
	if s.cfg.EnrichDNSViz {
		dnsviz.Apply(result)
	}
	s.applyStaticEnrichment(result)

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
	trace := s.ai.Apply(ctx, result, force)
	result.Meta.AI = &trace
	if trace.Status == "error" && trace.Error != "" {
		result.Meta.Warnings = append(result.Meta.Warnings, "AI registration analysis failed: "+trace.Error)
	}
	s.applyStaticEnrichment(result)
	return result, nil
}

func (s *Service) applyStaticEnrichment(result *model.LookupResult) {
	if result == nil {
		return
	}
	if s.cfg.EnrichRegistrar {
		registrarenrich.Apply(result, s.registrars)
	}
	if s.cfg.EnrichBrands {
		brand.Apply(result, s.brands)
	}
	if s.cfg.EnrichPricing {
		pricing.Apply(result, s.enrichment)
	}
	if s.cfg.EnrichMoz {
		moz.Apply(result, s.enrichment)
	}
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
	return fmt.Sprintf("%s:%s:rdap=%t:whois=%t:rs=%s:ws=%s:wf=%d:exact=%t", q.Type, q.Query, opts.UseRDAP, opts.UseWHOIS, opts.RDAPServer, opts.WHOISServer, opts.WHOISFollow, opts.ExactDomain)
}
