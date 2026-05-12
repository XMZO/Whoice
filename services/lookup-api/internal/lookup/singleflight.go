package lookup

import (
	"context"
	"sync"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type singleflight struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	done   chan struct{}
	result *model.LookupResult
	err    error
}

func newSingleflight() *singleflight {
	return &singleflight{calls: map[string]*flightCall{}}
}

func (g *singleflight) Do(ctx context.Context, key string, fn func(context.Context) (*model.LookupResult, error)) (*model.LookupResult, error) {
	g.mu.Lock()
	if call, ok := g.calls[key]; ok {
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
			return cloneResult(call.result), call.err
		}
	}

	call := &flightCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	call.result, call.err = fn(ctx)
	close(call.done)

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()

	return cloneResult(call.result), call.err
}

func cloneResult(result *model.LookupResult) *model.LookupResult {
	if result == nil {
		return nil
	}
	clone := *result
	clone.Source.Used = append([]model.SourceName(nil), result.Source.Used...)
	clone.Source.Errors = append([]model.SourceError(nil), result.Source.Errors...)
	clone.Statuses = append([]model.DomainStatus(nil), result.Statuses...)
	clone.Nameservers = append([]model.Nameserver(nil), result.Nameservers...)
	clone.Meta.Warnings = append([]string(nil), result.Meta.Warnings...)
	clone.Meta.Providers = append([]model.ProviderTrace(nil), result.Meta.Providers...)
	return &clone
}
