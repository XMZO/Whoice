package pricing

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

// Source is the replacement boundary for pricing data.
// Keep source-specific auth, cache, scraping, API, and import details behind this
// interface so the public config can stay a single pricing on/off switch.
type Source interface {
	Name() string
	Lookup(ctx context.Context, suffix string) (model.PricingInfo, bool, error)
}

type BackgroundSource interface {
	Start(context.Context)
}

type Resolver struct {
	sources []Source
	cache   *suffixCache
}

func NewDefaultResolver(dataDir string) *Resolver {
	return NewResolver(NewLocalSnapshotSource(dataDir))
}

func NewResolver(sources ...Source) *Resolver {
	items := make([]Source, 0, len(sources))
	for _, source := range sources {
		if source != nil {
			items = append(items, source)
		}
	}
	return &Resolver{sources: items}
}

func (r *Resolver) Lookup(ctx context.Context, suffix string) (model.PricingInfo, bool, error) {
	if r == nil {
		r = NewDefaultResolver("")
	}
	suffix = normalizeSuffix(suffix)
	if suffix == "" {
		return model.PricingInfo{}, false, nil
	}
	if r.cache != nil {
		return r.lookupCached(ctx, suffix)
	}
	return r.lookupSources(ctx, suffix)
}

func (r *Resolver) lookupSources(ctx context.Context, suffix string) (model.PricingInfo, bool, error) {
	info, ok, _, err := r.lookupSourcesDetailed(ctx, suffix)
	return info, ok, err
}

// lookupSourcesDetailed also reports whether an earlier source failed before
// one answered; such fallback answers are not cached.
func (r *Resolver) lookupSourcesDetailed(ctx context.Context, suffix string) (model.PricingInfo, bool, bool, error) {
	var problems []string
	for _, source := range r.sources {
		if source == nil {
			continue
		}
		info, ok, err := source.Lookup(ctx, suffix)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", source.Name(), err))
			continue
		}
		if !ok {
			continue
		}
		if info.Provider == "" {
			info.Provider = source.Name()
		}
		if info.Source == "" {
			info.Source = source.Name()
		}
		return info, true, len(problems) > 0, nil
	}
	if len(problems) > 0 {
		return model.PricingInfo{}, false, true, errors.New(strings.Join(problems, "; "))
	}
	return model.PricingInfo{}, false, false, nil
}

func (r *Resolver) Start(ctx context.Context) {
	if r == nil {
		return
	}
	for _, source := range r.sources {
		background, ok := source.(BackgroundSource)
		if ok {
			background.Start(ctx)
		}
	}
}

type Enricher struct {
	EnabledValue bool
	Resolver     *Resolver
}

func NewEnricher(enabled bool, resolver *Resolver) Enricher {
	return Enricher{EnabledValue: enabled, Resolver: resolver}
}

func (e Enricher) Name() string {
	return "pricing"
}

func (e Enricher) Enabled() bool {
	return e.EnabledValue
}

// Supports skips suffixes the cache already answered (CachedEnricher applied
// them with the first response), so only cache misses wait for deferred
// enrichment.
func (e Enricher) Supports(result *model.LookupResult) bool {
	if result == nil || result.Type != model.QueryDomain || result.Enrichment.Pricing != nil {
		return false
	}
	_, _, hit := e.Resolver.Cached(resultSuffix(result))
	return !hit
}

// CachedEnricher applies cached prices without touching any source, so it
// can run in the fast path before the lookup response is sent.
type CachedEnricher struct {
	EnabledValue bool
	Resolver     *Resolver
}

func (e CachedEnricher) Name() string  { return "pricing-cache" }
func (e CachedEnricher) Enabled() bool { return e.EnabledValue }

func (e CachedEnricher) Supports(result *model.LookupResult) bool {
	return result != nil && result.Type == model.QueryDomain && result.Enrichment.Pricing == nil
}

func (e CachedEnricher) Enrich(_ context.Context, result *model.LookupResult) error {
	if info, found, hit := e.Resolver.Cached(resultSuffix(result)); hit && found {
		result.Enrichment.Pricing = &info
	}
	return nil
}

func resultSuffix(result *model.LookupResult) string {
	if result.Domain.Suffix != "" {
		return result.Domain.Suffix
	}
	return domainSuffix(result.NormalizedQuery)
}

func (e Enricher) Enrich(ctx context.Context, result *model.LookupResult) error {
	return Apply(ctx, result, e.Resolver)
}

func Apply(ctx context.Context, result *model.LookupResult, resolver *Resolver) error {
	if result == nil || result.Type != model.QueryDomain {
		return nil
	}
	info, ok, err := resolver.Lookup(ctx, resultSuffix(result))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	result.Enrichment.Pricing = &info
	return nil
}

func domainSuffix(domain string) string {
	domain = normalizeSuffix(domain)
	for index, char := range domain {
		if char == '.' {
			return domain[index+1:]
		}
	}
	return domain
}

func normalizeSuffix(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
}
