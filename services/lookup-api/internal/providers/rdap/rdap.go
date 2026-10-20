package rdap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/rdapbootstrap"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

type Provider struct {
	client   *http.Client
	resolver rdapbootstrap.Resolver
}

func New(dataDir ...string) *Provider {
	dir := ""
	if len(dataDir) > 0 {
		dir = dataDir[0]
	}
	return &Provider{
		client: &http.Client{
			Timeout:   12 * time.Second,
			Transport: newTransport(),
		},
		resolver: rdapbootstrap.NewDefaultResolver(dir),
	}
}

// legacyRSASuites are AES suites with RSA key exchange (no forward secrecy).
// RC4 and 3DES stay disabled.
var legacyRSASuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// newTransport accepts TLS 1.2 RSA key exchange suites, which Go no longer
// offers by default. Some registries still serve RDAP with nothing else
// (rdap.nic.cat only negotiates AES128-SHA). RDAP data is public and
// read-only, and certificates are still verified.
func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(legacyRSASuites))
	for _, suite := range tls.CipherSuites() {
		suites = append(suites, suite.ID)
	}
	suites = append(suites, legacyRSASuites...)
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: suites}
	return transport
}

func (p *Provider) Name() model.SourceName {
	return model.SourceRDAP
}

func (p *Provider) Supports(q model.NormalizedQuery) bool {
	switch q.Type {
	case model.QueryDomain, model.QueryIPv4, model.QueryIPv6, model.QueryASN, model.QueryCIDR:
		return true
	default:
		return false
	}
}

func (p *Provider) Lookup(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) (*model.RawResponse, error) {
	start := time.Now()
	endpoint, err := p.endpointFor(ctx, q, opts.RDAPServer)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/XMZO/Whoice)")

	res, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	return &model.RawResponse{
		Source:      model.SourceRDAP,
		Server:      endpoint,
		Query:       q.Query,
		Body:        string(body),
		ContentType: res.Header.Get("Content-Type"),
		StatusCode:  res.StatusCode,
		ElapsedMs:   time.Since(start).Milliseconds(),
	}, nil
}

func (p *Provider) endpointFor(ctx context.Context, q model.NormalizedQuery, override string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(override), "/")
	if base == "" {
		if p.resolver != nil {
			if resolved, ok, err := p.resolver.BaseURL(ctx, q); err != nil {
				return "", providers.Skip(fmt.Sprintf("RDAP bootstrap lookup failed for %s %q: %v", q.Type, q.Query, err))
			} else if ok {
				base = resolved
			}
		}
		if base == "" {
			return "", providers.Skip(fmt.Sprintf("no RDAP bootstrap server for %s %q", q.Type, q.Query))
		}
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid RDAP server")
	}

	switch q.Type {
	case model.QueryDomain:
		return join(base, "domain", q.Query), nil
	case model.QueryIPv4, model.QueryIPv6:
		return join(base, "ip", q.Query), nil
	case model.QueryCIDR:
		ip, _, _ := strings.Cut(q.Query, "/")
		return join(base, "ip", ip), nil
	case model.QueryASN:
		return join(base, "autnum", strconv.FormatUint(uint64(q.ASN), 10)), nil
	default:
		return "", fmt.Errorf("RDAP does not support query type %q", q.Type)
	}
}

func join(base string, parts ...string) string {
	path := strings.TrimRight(base, "/")
	for _, part := range parts {
		path += "/" + url.PathEscape(part)
	}
	return path
}
