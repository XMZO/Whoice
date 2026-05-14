package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Enricher interface {
	Name() string
	Enabled() bool
	Supports(*model.LookupResult) bool
	Enrich(context.Context, *model.LookupResult) error
}

type Step struct {
	NameValue    string
	EnabledValue bool
	SupportsFunc func(*model.LookupResult) bool
	EnrichFunc   func(context.Context, *model.LookupResult) error
	TimeoutValue time.Duration
}

func (s Step) Name() string {
	if s.NameValue == "" {
		return "unknown"
	}
	return s.NameValue
}

func (s Step) Enabled() bool {
	return s.EnabledValue
}

func (s Step) Supports(result *model.LookupResult) bool {
	if s.SupportsFunc == nil {
		return true
	}
	return s.SupportsFunc(result)
}

func (s Step) Enrich(ctx context.Context, result *model.LookupResult) error {
	if s.EnrichFunc == nil {
		return nil
	}
	return s.EnrichFunc(ctx, result)
}

func (s Step) Timeout() time.Duration {
	return s.TimeoutValue
}

type Pipeline struct {
	enrichers []Enricher
}

func New(enrichers ...Enricher) Pipeline {
	items := make([]Enricher, 0, len(enrichers))
	for _, enricher := range enrichers {
		if enricher != nil {
			items = append(items, enricher)
		}
	}
	return Pipeline{enrichers: items}
}

func (p Pipeline) Run(ctx context.Context, result *model.LookupResult) {
	if result == nil {
		return
	}
	for _, enricher := range p.enrichers {
		if enricher == nil || !enricher.Enabled() || !enricher.Supports(result) {
			continue
		}
		runCtx := ctx
		cancel := func() {}
		if timed, ok := enricher.(interface{ Timeout() time.Duration }); ok {
			if timeout := timed.Timeout(); timeout > 0 {
				runCtx, cancel = context.WithTimeout(ctx, timeout)
			}
		}
		err := enricher.Enrich(runCtx, result)
		cancel()
		if err != nil {
			result.Meta.Warnings = append(result.Meta.Warnings, fmt.Sprintf("%s enrichment failed: %v", enricher.Name(), err))
		}
	}
}

func (p Pipeline) Names() []string {
	names := make([]string, 0, len(p.enrichers))
	for _, enricher := range p.enrichers {
		if enricher != nil {
			names = append(names, enricher.Name())
		}
	}
	return names
}

func (p Pipeline) PendingNames(result *model.LookupResult) []string {
	if result == nil {
		return nil
	}
	names := make([]string, 0, len(p.enrichers))
	for _, enricher := range p.enrichers {
		if enricher == nil || !enricher.Enabled() || !enricher.Supports(result) {
			continue
		}
		names = append(names, enricher.Name())
	}
	return names
}
