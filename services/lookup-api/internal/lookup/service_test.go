package lookup

import (
	"context"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	providerapi "github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

type testProvider struct {
	source model.SourceName
	raw    *model.RawResponse
	err    error
}

func (p testProvider) Name() model.SourceName {
	return p.source
}

func (p testProvider) Supports(q model.NormalizedQuery) bool {
	return q.Type == model.QueryDomain
}

func (p testProvider) Lookup(_ context.Context, q model.NormalizedQuery, _ model.LookupOptions) (*model.RawResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	raw := *p.raw
	raw.Query = q.Query
	return &raw, nil
}

func TestLookupSkipsUnavailableRDAPAndUsesWHOIS(t *testing.T) {
	service := NewService(config.Config{
		LookupTimeout:    time.Second,
		ProviderTimeout:  time.Second,
		RDAPEnabled:      true,
		WHOISEnabled:     true,
		WHOISFollowLimit: 1,
	}, []providerapi.Provider{
		testProvider{
			source: model.SourceRDAP,
			err:    providerapi.Skip(`no RDAP bootstrap server for domain "example.test"`),
		},
		testProvider{
			source: model.SourceWHOIS,
			raw: &model.RawResponse{
				Source: model.SourceWHOIS,
				Server: "whois.example.test",
				Body:   "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\nName Server: NS1.EXAMPLE.TEST\n",
			},
		},
	}, parsers.NewRegistry(parsers.WHOISParser{}))

	result, err := service.Lookup(context.Background(), "example.test", model.LookupOptions{
		UseRDAP:       true,
		UseWHOIS:      true,
		LookupLimit:   time.Second,
		ProviderLimit: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source.Primary != model.SourceWHOIS {
		t.Fatalf("primary source: got %q want whois", result.Source.Primary)
	}
	if len(result.Source.Errors) != 0 {
		t.Fatalf("skipped RDAP should not become source error: %#v", result.Source.Errors)
	}
	var sawSkippedRDAP bool
	for _, trace := range result.Meta.Providers {
		if trace.Source == model.SourceRDAP && trace.Status == "skipped" {
			sawSkippedRDAP = true
		}
	}
	if !sawSkippedRDAP {
		t.Fatalf("expected skipped RDAP trace, got %#v", result.Meta.Providers)
	}
}
