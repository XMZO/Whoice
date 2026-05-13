package rdap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

func TestEndpointForQueryTypes(t *testing.T) {
	provider := &Provider{}
	tests := []struct {
		name string
		q    model.NormalizedQuery
		want string
	}{
		{
			name: "domain",
			q: model.NormalizedQuery{
				Query: "example.com",
				Type:  model.QueryDomain,
			},
			want: "https://rdap.example.test/domain/example.com",
		},
		{
			name: "ipv4",
			q: model.NormalizedQuery{
				Query: "192.0.2.1",
				Type:  model.QueryIPv4,
			},
			want: "https://rdap.example.test/ip/192.0.2.1",
		},
		{
			name: "ipv6",
			q: model.NormalizedQuery{
				Query: "2001:db8::1",
				Type:  model.QueryIPv6,
			},
			want: "https://rdap.example.test/ip/2001:db8::1",
		},
		{
			name: "cidr",
			q: model.NormalizedQuery{
				Query: "2001:db8::/32",
				Type:  model.QueryCIDR,
			},
			want: "https://rdap.example.test/ip/2001:db8::",
		},
		{
			name: "asn",
			q: model.NormalizedQuery{
				Query: "AS64496",
				Type:  model.QueryASN,
				ASN:   64496,
			},
			want: "https://rdap.example.test/autnum/64496",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := provider.endpointFor(context.Background(), tt.q, "https://rdap.example.test")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("endpoint: got %q want %q", got, tt.want)
			}
		})
	}
}

type resolverFunc func(model.NormalizedQuery) (string, bool, error)

func (f resolverFunc) BaseURL(_ context.Context, q model.NormalizedQuery) (string, bool, error) {
	return f(q)
}

func TestEndpointForRequiresBootstrapMatchWithoutOverride(t *testing.T) {
	provider := &Provider{
		resolver: resolverFunc(func(model.NormalizedQuery) (string, bool, error) {
			return "", false, nil
		}),
	}

	_, err := provider.endpointFor(context.Background(), model.NormalizedQuery{
		Query: "example.invalid",
		Type:  model.QueryDomain,
	}, "")
	if err == nil {
		t.Fatal("expected missing bootstrap error")
	}
	if strings.Contains(err.Error(), "rdap.org") {
		t.Fatalf("missing bootstrap error should not mention rdap.org: %v", err)
	}
	if !strings.Contains(err.Error(), "no RDAP bootstrap server") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEndpointForUsesBootstrapMatch(t *testing.T) {
	provider := &Provider{
		resolver: resolverFunc(func(q model.NormalizedQuery) (string, bool, error) {
			if q.Type != model.QueryDomain || q.Query != "example.test" {
				t.Fatalf("unexpected query: %#v", q)
			}
			return "https://rdap.bootstrap.test/", true, nil
		}),
	}

	got, err := provider.endpointFor(context.Background(), model.NormalizedQuery{
		Query: "example.test",
		Type:  model.QueryDomain,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://rdap.bootstrap.test/domain/example.test" {
		t.Fatalf("endpoint: got %q", got)
	}
}

func TestEndpointForTreatsBootstrapErrorAsSkip(t *testing.T) {
	provider := &Provider{
		resolver: resolverFunc(func(model.NormalizedQuery) (string, bool, error) {
			return "", false, errors.New("network timeout")
		}),
	}

	_, err := provider.endpointFor(context.Background(), model.NormalizedQuery{
		Query: "example.test",
		Type:  model.QueryDomain,
	}, "")
	if err == nil {
		t.Fatal("expected bootstrap skip error")
	}
	if !providers.IsSkip(err) {
		t.Fatalf("expected skip error, got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "RDAP bootstrap lookup failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
