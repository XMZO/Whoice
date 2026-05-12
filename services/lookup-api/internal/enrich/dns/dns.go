package dns

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

func Apply(ctx context.Context, result *model.LookupResult, timeout time.Duration) {
	ApplyWithResolver(ctx, result, timeout, net.DefaultResolver)
}

func ApplyWithResolver(ctx context.Context, result *model.LookupResult, timeout time.Duration, resolver Resolver) {
	if result == nil || result.Type != model.QueryDomain || result.NormalizedQuery == "" || resolver == nil {
		return
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	start := time.Now()
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := strings.TrimSuffix(result.NormalizedQuery, ".")
	info := &model.DNSInfo{}

	if cname, err := resolver.LookupCNAME(lookupCtx, host); err == nil {
		info.CNAME = strings.ToLower(strings.TrimSuffix(cname, "."))
	}
	if addrs, err := resolver.LookupIPAddr(lookupCtx, host); err == nil {
		for _, addr := range addrs {
			if addr.IP == nil {
				continue
			}
			value := model.DNSAddress{IP: addr.IP.String()}
			if addr.IP.To4() != nil {
				value.Version = "ipv4"
				info.A = append(info.A, value)
			} else {
				value.Version = "ipv6"
				info.AAAA = append(info.AAAA, value)
			}
		}
		sortAddresses(info.A)
		sortAddresses(info.AAAA)
	}
	if records, err := resolver.LookupMX(lookupCtx, host); err == nil {
		for _, record := range records {
			if record == nil {
				continue
			}
			info.MX = append(info.MX, model.DNSMX{
				Host: strings.ToLower(strings.TrimSuffix(record.Host, ".")),
				Pref: record.Pref,
			})
		}
		sort.Slice(info.MX, func(i, j int) bool {
			if info.MX[i].Pref == info.MX[j].Pref {
				return info.MX[i].Host < info.MX[j].Host
			}
			return info.MX[i].Pref < info.MX[j].Pref
		})
	}
	if records, err := resolver.LookupNS(lookupCtx, host); err == nil {
		for _, record := range records {
			if record == nil {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(record.Host, "."))
			if name != "" {
				info.NS = append(info.NS, name)
			}
		}
		sort.Strings(info.NS)
	}

	info.ElapsedMs = time.Since(start).Milliseconds()
	if len(info.A) == 0 && len(info.AAAA) == 0 && info.CNAME == "" && len(info.MX) == 0 && len(info.NS) == 0 {
		result.Meta.Warnings = append(result.Meta.Warnings, "DNS enrichment returned no records")
		return
	}
	result.Enrichment.DNS = info
}

func sortAddresses(values []model.DNSAddress) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].IP < values[j].IP
	})
}
