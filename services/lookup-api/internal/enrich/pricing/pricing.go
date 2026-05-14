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
		return info, true, nil
	}
	if len(problems) > 0 {
		return model.PricingInfo{}, false, errors.New(strings.Join(problems, "; "))
	}
	return model.PricingInfo{}, false, nil
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

func (e Enricher) Supports(result *model.LookupResult) bool {
	return result != nil && result.Type == model.QueryDomain && result.Enrichment.Pricing == nil
}

func (e Enricher) Enrich(ctx context.Context, result *model.LookupResult) error {
	return Apply(ctx, result, e.Resolver)
}

func Apply(ctx context.Context, result *model.LookupResult, resolver *Resolver) error {
	if result == nil || result.Type != model.QueryDomain {
		return nil
	}
	suffix := result.Domain.Suffix
	if suffix == "" {
		suffix = domainSuffix(result.NormalizedQuery)
	}
	info, ok, err := resolver.Lookup(ctx, suffix)
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
