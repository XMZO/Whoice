package providers

import (
	"context"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Provider interface {
	Name() model.SourceName
	Supports(q model.NormalizedQuery) bool
	Lookup(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) (*model.RawResponse, error)
}
