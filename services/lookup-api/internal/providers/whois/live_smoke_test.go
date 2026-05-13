package whois

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestLiveWHOISSmoke(t *testing.T) {
	if os.Getenv("WHOICE_LIVE_WHOIS_SMOKE") != "1" {
		t.Skip("set WHOICE_LIVE_WHOIS_SMOKE=1 to run TCP WHOIS smoke checks")
	}

	cases := []struct {
		name        string
		query       model.NormalizedQuery
		wantServer  string
		wantSnippet string
	}{
		{
			name: "verisign-com-template",
			query: model.NormalizedQuery{
				Type:             model.QueryDomain,
				Query:            "example.com",
				Suffix:           "com",
				RegisteredDomain: "example.com",
			},
			wantServer:  "whois.verisign-grs.com",
			wantSnippet: "EXAMPLE.COM",
		},
	}

	provider := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			raw, err := provider.Lookup(ctx, tc.query, model.LookupOptions{
				UseWHOIS:      true,
				ProviderLimit: 10 * time.Second,
				WHOISFollow:   0,
			})
			if err != nil {
				t.Fatal(err)
			}
			if raw == nil || strings.TrimSpace(raw.Body) == "" {
				t.Fatal("expected non-empty live WHOIS response")
			}
			if !strings.Contains(raw.Server, tc.wantServer) {
				t.Fatalf("server: got %q want %q", raw.Server, tc.wantServer)
			}
			if !strings.Contains(strings.ToUpper(raw.Body), tc.wantSnippet) {
				t.Fatalf("live WHOIS response did not contain %q", tc.wantSnippet)
			}
		})
	}
}
