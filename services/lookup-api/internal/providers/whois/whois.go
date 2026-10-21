package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/whoisservers"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
	"golang.org/x/text/encoding/charmap"
)

var referralPattern = regexp.MustCompile(`(?im)^\s*(?:whois|refer):\s*([a-z0-9.-]+)\s*$`)

const (
	maxWHOISResponseBytes = 2 * 1024 * 1024
	ianaServer            = "whois.iana.org"
)

type Provider struct {
	resolver whoisservers.Resolver
}

func New(dataDir ...string) *Provider {
	return &Provider{resolver: whoisservers.NewResolver(dataDir...)}
}

func (p *Provider) Name() model.SourceName {
	return model.SourceWHOIS
}

func (p *Provider) Supports(q model.NormalizedQuery) bool {
	switch q.Type {
	case model.QueryDomain, model.QueryIPv4, model.QueryIPv6, model.QueryASN:
		return true
	default:
		return false
	}
}

func (p *Provider) Lookup(ctx context.Context, q model.NormalizedQuery, opts model.LookupOptions) (*model.RawResponse, error) {
	start := time.Now()
	server, query, err := p.resolver.Resolve(q, opts.WHOISServer)
	if err != nil {
		return nil, err
	}
	// Under a private suffix (us.ci, github.io) the TLD registry's WHOIS has
	// no records; only a server listed for the suffix itself is useful.
	if q.Type == model.QueryDomain && q.PrivateSuffix && opts.WHOISServer == "" {
		tld := tldOf(model.NormalizedQuery{Query: q.Suffix})
		tldServer, _, _ := p.resolver.Resolve(model.NormalizedQuery{Type: model.QueryDomain, Query: tld, Suffix: tld}, "")
		if strings.EqualFold(tldServer.Host, server.Host) {
			return nil, providers.Skip(fmt.Sprintf("no WHOIS server for names under %s", q.Suffix))
		}
	}

	body, err := queryServer(ctx, server.Host, query, opts.ProviderLimit)
	if err != nil {
		return nil, err
	}
	usedServers := []string{server.Host}

	if opts.WHOISServer == "" {
		followLimit := opts.WHOISFollow
		if followLimit < 0 {
			followLimit = 0
		}
		for i := 0; i < followLimit; i++ {
			referral := findReferral(body)
			if referral == "" || containsServer(usedServers, referral) {
				break
			}
			referredBody, err := queryServer(ctx, referral, query, opts.ProviderLimit)
			if err != nil {
				break
			}
			body = body + "\n\n--- " + referral + " ---\n" + referredBody
			usedServers = append(usedServers, referral)
		}
	}

	// For a domain without a known registry server the query goes to IANA,
	// which answers with the TLD record. Without a referral that record says
	// nothing about the domain itself.
	// A registry that refuses the query answers with a notice, not a record;
	// treat it as a failure so it is not read as registration data.
	if refusal := refusalPattern.FindString(body); refusal != "" {
		return nil, fmt.Errorf("%s refused the query: %s", server.Host, strings.TrimSpace(refusal))
	}
	if opts.WHOISServer == "" && isBareIANATLDRecord(q, usedServers) {
		if referral := findReferral(body); referral != "" {
			return nil, fmt.Errorf("the .%s registry WHOIS server %s did not answer", tldOf(q), referral)
		}
		return nil, providers.Skip(fmt.Sprintf("the registry for .%s publishes no WHOIS service", tldOf(q)))
	}

	return &model.RawResponse{
		Source:    model.SourceWHOIS,
		Server:    strings.Join(usedServers, ", "),
		Query:     query,
		Body:      body,
		ElapsedMs: time.Since(start).Milliseconds(),
	}, nil
}

func queryServer(ctx context.Context, server, query string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if !strings.Contains(server, ":") {
		server += ":43"
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}

	body, err := io.ReadAll(io.LimitReader(conn, maxWHOISResponseBytes))
	if err != nil {
		return "", err
	}

	return decodeWHOISBody(body), nil
}

func decodeWHOISBody(body []byte) string {
	if utf8.Valid(body) {
		return string(body)
	}
	for _, decoder := range []interface {
		Bytes([]byte) ([]byte, error)
	}{
		charmap.Windows1252.NewDecoder(),
		charmap.ISO8859_1.NewDecoder(),
	} {
		decoded, err := decoder.Bytes(body)
		if err == nil && utf8.Valid(decoded) {
			return string(decoded)
		}
	}
	return strings.ToValidUTF8(string(body), "\uFFFD")
}

func findReferral(body string) string {
	matches := referralPattern.FindStringSubmatch(body)
	if matches == nil {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func containsServer(servers []string, server string) bool {
	server = strings.ToLower(strings.TrimSpace(server))
	for _, item := range servers {
		if strings.ToLower(strings.TrimSpace(item)) == server {
			return true
		}
	}
	return false
}

// refusalPattern matches registry notices that decline to answer: blocked
// clients, rate limits, or a server that rejects the query format.
var refusalPattern = regexp.MustCompile(`(?im)^.*(?:requests of this client are not permitted|solo acepta consultas|(?:query|request|rate|connection) ?limit (?:exceeded|reached)|maximum (?:number of )?(?:queries|requests|query rate)|too many (?:queries|requests|connections)|access (?:has been )?denied|you have exceeded|temporarily (?:blocked|denied|unavailable)|try again later).*$`)

func tldOf(q model.NormalizedQuery) string {
	name := strings.Trim(q.Query, ".")
	if index := strings.LastIndex(name, "."); index >= 0 {
		return name[index+1:]
	}
	return name
}

// isBareIANATLDRecord reports that a domain query got nothing beyond the
// IANA record of its TLD: the TLD has no WHOIS (no referral), or the
// referred registry server did not answer.
func isBareIANATLDRecord(q model.NormalizedQuery, usedServers []string) bool {
	return q.Type == model.QueryDomain && len(usedServers) == 1 && strings.EqualFold(usedServers[0], ianaServer)
}
