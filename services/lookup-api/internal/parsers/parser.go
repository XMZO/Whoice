package parsers

import (
	"context"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Parser interface {
	Name() string
	Supports(raw model.RawResponse) bool
	Priority() int
	Parse(ctx context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error)
}

type Registry struct {
	parsers []Parser
}

func NewRegistry(parsers ...Parser) *Registry {
	return &Registry{parsers: parsers}
}

func (r *Registry) Parse(ctx context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	var selected Parser
	for _, parser := range r.parsers {
		if !parser.Supports(raw) {
			continue
		}
		if selected == nil || parser.Priority() > selected.Priority() {
			selected = parser
		}
	}
	if selected == nil {
		return &model.PartialResult{
			Source:   raw.Source,
			Status:   model.StatusUnknown,
			Warnings: []string{"no parser available for raw response"},
		}, nil
	}
	return selected.Parse(ctx, raw, q)
}
