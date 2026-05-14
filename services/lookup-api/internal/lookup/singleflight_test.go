package lookup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func TestSingleflightCoalescesConcurrentCalls(t *testing.T) {
	group := newSingleflight()
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})

	fn := func(context.Context) (*model.LookupResult, error) {
		calls.Add(1)
		close(started)
		<-release
		return &model.LookupResult{NormalizedQuery: "example.com"}, nil
	}

	var wg sync.WaitGroup
	results := make(chan *model.LookupResult, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := group.Do(context.Background(), "same", fn)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			results <- result
		}()
	}

	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	if got := calls.Load(); got != 1 {
		t.Fatalf("calls: got %d want 1", got)
	}
	for result := range results {
		if result.NormalizedQuery != "example.com" {
			t.Fatalf("unexpected result: %#v", result)
		}
	}
}

func TestCloneResultKeepsEmptyCollectionsNonNil(t *testing.T) {
	result := cloneResult(&model.LookupResult{
		Source:      model.SourceInfo{Used: []model.SourceName{}},
		Statuses:    []model.DomainStatus{},
		Nameservers: []model.Nameserver{},
	})

	if result.Source.Used == nil {
		t.Fatal("source.used should stay an empty slice, not nil")
	}
	if result.Statuses == nil {
		t.Fatal("statuses should stay an empty slice, not nil")
	}
	if result.Nameservers == nil {
		t.Fatal("nameservers should stay an empty slice, not nil")
	}
}

func TestCloneResultCopiesNameserverAddresses(t *testing.T) {
	original := &model.LookupResult{
		Nameservers: []model.Nameserver{
			{Host: "alice.ns.cloudflare.com", Addresses: []string{"173.245.58.60"}},
		},
	}

	clone := cloneResult(original)
	clone.Nameservers[0].Addresses[0] = "203.0.113.1"

	if original.Nameservers[0].Addresses[0] != "173.245.58.60" {
		t.Fatalf("clone mutated original nameserver address: %#v", original.Nameservers[0].Addresses)
	}
}

func TestCloneResultCopiesPhase4EnrichmentPointers(t *testing.T) {
	register := 9.99
	renew := 12.34
	renewCNY := 83.72
	original := &model.LookupResult{
		Enrichment: model.EnrichmentInfo{
			DNSViz: &model.DNSVizInfo{URL: "https://dnsviz.net/d/example.com/dnssec/"},
			Pricing: &model.PricingInfo{
				Register:   &register,
				Currency:   "USD",
				RenewOffer: &model.PricingOffer{Price: &renew, PriceCNY: &renewCNY},
			},
			Moz: &model.MozInfo{DomainAuthority: 93},
		},
	}

	clone := cloneResult(original)
	clone.Enrichment.DNSViz.URL = "https://changed.example"
	*clone.Enrichment.Pricing.Register = 1.23
	*clone.Enrichment.Pricing.RenewOffer.Price = 4.56
	*clone.Enrichment.Pricing.RenewOffer.PriceCNY = 7.89
	clone.Enrichment.Moz.DomainAuthority = 1

	if original.Enrichment.DNSViz.URL != "https://dnsviz.net/d/example.com/dnssec/" {
		t.Fatalf("clone mutated DNSViz: %#v", original.Enrichment.DNSViz)
	}
	if *original.Enrichment.Pricing.Register != 9.99 {
		t.Fatalf("clone mutated pricing: %#v", original.Enrichment.Pricing)
	}
	if *original.Enrichment.Pricing.RenewOffer.Price != 12.34 || *original.Enrichment.Pricing.RenewOffer.PriceCNY != 83.72 {
		t.Fatalf("clone mutated pricing offer: %#v", original.Enrichment.Pricing.RenewOffer)
	}
	if original.Enrichment.Moz.DomainAuthority != 93 {
		t.Fatalf("clone mutated moz: %#v", original.Enrichment.Moz)
	}
}
