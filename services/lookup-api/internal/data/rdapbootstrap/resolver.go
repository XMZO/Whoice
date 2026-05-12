package rdapbootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

const (
	DNSBootstrapURL  = "https://data.iana.org/rdap/dns.json"
	IPv4BootstrapURL = "https://data.iana.org/rdap/ipv4.json"
	IPv6BootstrapURL = "https://data.iana.org/rdap/ipv6.json"
	ASNBootstrapURL  = "https://data.iana.org/rdap/asn.json"
)

type Resolver interface {
	BaseURL(ctx context.Context, q model.NormalizedQuery) (string, bool, error)
}

type HTTPResolver struct {
	client *http.Client
	ttl    time.Duration
	urls   URLs
	mu     sync.Mutex
	cache  map[string]cachedFile
}

type URLs struct {
	DNS  string
	IPv4 string
	IPv6 string
	ASN  string
}

type cachedFile struct {
	file      bootstrapFile
	expiresAt time.Time
}

type bootstrapFile struct {
	Services [][][]string `json:"services"`
}

func NewHTTPResolver() *HTTPResolver {
	return &HTTPResolver{
		client: &http.Client{Timeout: 10 * time.Second},
		ttl:    24 * time.Hour,
		urls: URLs{
			DNS:  DNSBootstrapURL,
			IPv4: IPv4BootstrapURL,
			IPv6: IPv6BootstrapURL,
			ASN:  ASNBootstrapURL,
		},
		cache: map[string]cachedFile{},
	}
}

func (r *HTTPResolver) BaseURL(ctx context.Context, q model.NormalizedQuery) (string, bool, error) {
	kind, key, err := bootstrapKindAndKey(q)
	if err != nil {
		return "", false, err
	}
	file, err := r.file(ctx, kind)
	if err != nil {
		return "", false, err
	}

	switch kind {
	case "dns":
		return matchDNS(file, key)
	case "ipv4", "ipv6":
		return matchIP(file, key)
	case "asn":
		return matchASN(file, q.ASN)
	default:
		return "", false, fmt.Errorf("unsupported RDAP bootstrap kind %q", kind)
	}
}

func (r *HTTPResolver) file(ctx context.Context, kind string) (bootstrapFile, error) {
	r.mu.Lock()
	if cached, ok := r.cache[kind]; ok && time.Now().Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.file, nil
	}
	r.mu.Unlock()

	endpoint := r.urlFor(kind)
	if endpoint == "" {
		return bootstrapFile{}, fmt.Errorf("missing RDAP bootstrap URL for %s", kind)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return bootstrapFile{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/XMZO/Whoice)")

	res, err := r.client.Do(req)
	if err != nil {
		return bootstrapFile{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return bootstrapFile{}, fmt.Errorf("RDAP bootstrap %s returned HTTP %d", kind, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024))
	if err != nil {
		return bootstrapFile{}, err
	}
	var file bootstrapFile
	if err := json.Unmarshal(body, &file); err != nil {
		return bootstrapFile{}, err
	}

	r.mu.Lock()
	r.cache[kind] = cachedFile{file: file, expiresAt: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return file, nil
}

func (r *HTTPResolver) urlFor(kind string) string {
	switch kind {
	case "dns":
		return r.urls.DNS
	case "ipv4":
		return r.urls.IPv4
	case "ipv6":
		return r.urls.IPv6
	case "asn":
		return r.urls.ASN
	default:
		return ""
	}
}

func bootstrapKindAndKey(q model.NormalizedQuery) (string, string, error) {
	switch q.Type {
	case model.QueryDomain:
		if q.Query == "" {
			return "", "", errors.New("empty domain")
		}
		return "dns", strings.Trim(strings.ToLower(q.Query), "."), nil
	case model.QueryIPv4:
		return "ipv4", q.Query, nil
	case model.QueryIPv6:
		return "ipv6", q.Query, nil
	case model.QueryCIDR:
		ip, _, ok := strings.Cut(q.Query, "/")
		if !ok {
			return "", "", fmt.Errorf("invalid CIDR query %q", q.Query)
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return "", "", err
		}
		if addr.Is4() {
			return "ipv4", addr.String(), nil
		}
		return "ipv6", addr.String(), nil
	case model.QueryASN:
		return "asn", q.Query, nil
	default:
		return "", "", fmt.Errorf("RDAP bootstrap does not support %q", q.Type)
	}
}

func matchDNS(file bootstrapFile, domain string) (string, bool, error) {
	bestLabels := -1
	bestURL := ""
	for _, service := range file.Services {
		if len(service) < 2 {
			continue
		}
		for _, entry := range service[0] {
			entry = strings.Trim(strings.ToLower(entry), ".")
			if entry == "" {
				continue
			}
			if domain != entry && !strings.HasSuffix(domain, "."+entry) {
				continue
			}
			labels := strings.Count(entry, ".") + 1
			if labels > bestLabels {
				if base := firstURL(service[1]); base != "" {
					bestLabels = labels
					bestURL = base
				}
			}
		}
	}
	return bestURL, bestURL != "", nil
}

func matchIP(file bootstrapFile, value string) (string, bool, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", false, err
	}
	bestBits := -1
	bestURL := ""
	for _, service := range file.Services {
		if len(service) < 2 {
			continue
		}
		for _, entry := range service[0] {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil || !prefix.Contains(addr) {
				continue
			}
			if prefix.Bits() > bestBits {
				if base := firstURL(service[1]); base != "" {
					bestBits = prefix.Bits()
					bestURL = base
				}
			}
		}
	}
	return bestURL, bestURL != "", nil
}

func matchASN(file bootstrapFile, asn uint32) (string, bool, error) {
	for _, service := range file.Services {
		if len(service) < 2 {
			continue
		}
		for _, entry := range service[0] {
			start, end, ok := parseASNRange(entry)
			if !ok {
				continue
			}
			if asn >= start && asn <= end {
				base := firstURL(service[1])
				return base, base != "", nil
			}
		}
	}
	return "", false, nil
}

func parseASNRange(value string) (uint32, uint32, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, false
	}
	left, right, hasRange := strings.Cut(value, "-")
	if !hasRange {
		right = left
	}
	start, err := strconv.ParseUint(strings.TrimSpace(left), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	end, err := strconv.ParseUint(strings.TrimSpace(right), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if start > end {
		return 0, 0, false
	}
	return uint32(start), uint32(end), true
}

func firstURL(values []string) string {
	for _, value := range values {
		if strings.HasPrefix(value, "https://") {
			return value
		}
	}
	for _, value := range values {
		if strings.HasPrefix(value, "http://") {
			return value
		}
	}
	return ""
}
