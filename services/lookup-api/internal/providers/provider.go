package providers

import (
	"context"
	"errors"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Provider interface {
	Name() model.SourceName
	Supports(q model.NormalizedQuery) bool
	Lookup(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) (*model.RawResponse, error)
}

type SkipError struct {
	Reason string
}

func (e SkipError) Error() string {
	return e.Reason
}

func Skip(reason string) error {
	return SkipError{Reason: reason}
}

func IsSkip(err error) bool {
	var skip SkipError
	return errors.As(err, &skip)
}
