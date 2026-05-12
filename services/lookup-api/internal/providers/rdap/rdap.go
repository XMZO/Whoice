package rdap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/rdapbootstrap"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
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
			Timeout: 12 * time.Second,
		},
		resolver: rdapbootstrap.NewDefaultResolver(dir),
	}
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
	base := strings.TrimRight(override, "/")
	if base == "" {
		if p.resolver != nil {
			if resolved, ok, err := p.resolver.BaseURL(ctx, q); err != nil {
				return "", err
			} else if ok {
				base = resolved
			}
		}
		if base == "" {
			base = "https://rdap.org"
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
