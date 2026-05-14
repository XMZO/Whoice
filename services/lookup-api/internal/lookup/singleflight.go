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
	clone.Source.Used = cloneSourceNames(result.Source.Used)
	clone.Source.Errors = append([]model.SourceError(nil), result.Source.Errors...)
	clone.Statuses = cloneDomainStatuses(result.Statuses)
	clone.Nameservers = cloneNameservers(result.Nameservers)
	clone.Registrant.Extra = cloneRegistrationFields(result.Registrant.Extra)
	clone.Registrant.FieldSources = cloneRegistrationFieldSources(result.Registrant.FieldSources)
	clone.Enrichment.DNS = cloneDNSInfo(result.Enrichment.DNS)
	clone.Enrichment.DNSViz = cloneDNSVizInfo(result.Enrichment.DNSViz)
	clone.Enrichment.Pricing = clonePricingInfo(result.Enrichment.Pricing)
	clone.Enrichment.Moz = cloneMozInfo(result.Enrichment.Moz)
	if result.Registrar.Brand != nil {
		brand := *result.Registrar.Brand
		clone.Registrar.Brand = &brand
	}
	clone.Meta.Warnings = append([]string(nil), result.Meta.Warnings...)
	clone.Meta.Providers = append([]model.ProviderTrace(nil), result.Meta.Providers...)
	if result.Meta.AI != nil {
		ai := *result.Meta.AI
		ai.Applied = append([]string(nil), result.Meta.AI.Applied...)
		clone.Meta.AI = &ai
	}
	return &clone
}

func cloneSourceNames(values []model.SourceName) []model.SourceName {
	out := make([]model.SourceName, len(values))
	copy(out, values)
	return out
}

func cloneDomainStatuses(values []model.DomainStatus) []model.DomainStatus {
	out := make([]model.DomainStatus, len(values))
	copy(out, values)
	return out
}

func cloneNameservers(values []model.Nameserver) []model.Nameserver {
	out := make([]model.Nameserver, len(values))
	copy(out, values)
	for i := range out {
		out[i].Addresses = append([]string(nil), values[i].Addresses...)
		if values[i].Brand != nil {
			brand := *values[i].Brand
			out[i].Brand = &brand
		}
	}
	return out
}

func cloneRegistrationFields(values []model.RegistrationField) []model.RegistrationField {
	out := make([]model.RegistrationField, len(values))
	copy(out, values)
	for i := range out {
		if values[i].Confidence != nil {
			confidence := *values[i].Confidence
			out[i].Confidence = &confidence
		}
	}
	return out
}

func cloneRegistrationFieldSources(values map[string][]model.RegistrationField) map[string][]model.RegistrationField {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string][]model.RegistrationField, len(values))
	for key, fields := range values {
		out[key] = cloneRegistrationFields(fields)
	}
	return out
}

func cloneDNSInfo(info *model.DNSInfo) *model.DNSInfo {
	if info == nil {
		return nil
	}
	clone := *info
	clone.A = append([]model.DNSAddress(nil), info.A...)
	clone.AAAA = append([]model.DNSAddress(nil), info.AAAA...)
	clone.MX = append([]model.DNSMX(nil), info.MX...)
	clone.NS = append([]string(nil), info.NS...)
	clone.RegistryNS = append([]string(nil), info.RegistryNS...)
	clone.Resolvers = append([]model.DNSResolverInfo(nil), info.Resolvers...)
	return &clone
}

func cloneDNSVizInfo(info *model.DNSVizInfo) *model.DNSVizInfo {
	if info == nil {
		return nil
	}
	clone := *info
	return &clone
}

func clonePricingInfo(info *model.PricingInfo) *model.PricingInfo {
	if info == nil {
		return nil
	}
	clone := *info
	if info.Register != nil {
		value := *info.Register
		clone.Register = &value
	}
	if info.Renew != nil {
		value := *info.Renew
		clone.Renew = &value
	}
	if info.Transfer != nil {
		value := *info.Transfer
		clone.Transfer = &value
	}
	clone.RegisterOffer = clonePricingOffer(info.RegisterOffer)
	clone.RenewOffer = clonePricingOffer(info.RenewOffer)
	clone.TransferOffer = clonePricingOffer(info.TransferOffer)
	return &clone
}

func clonePricingOffer(info *model.PricingOffer) *model.PricingOffer {
	if info == nil {
		return nil
	}
	clone := *info
	if info.Price != nil {
		value := *info.Price
		clone.Price = &value
	}
	if info.PriceCNY != nil {
		value := *info.PriceCNY
		clone.PriceCNY = &value
	}
	return &clone
}

func cloneMozInfo(info *model.MozInfo) *model.MozInfo {
	if info == nil {
		return nil
	}
	clone := *info
	return &clone
}
