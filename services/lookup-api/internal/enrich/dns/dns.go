package dns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"golang.org/x/net/dns/dnsmessage"
)

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
}

type MultiResolver interface {
	Resolvers() []Resolver
}

type IPAnswer struct {
	Addr     net.IPAddr
	Source   string
	Resolver string
	Endpoint string
}

type dohLookupResult struct {
	A         []IPAnswer
	AAAA      []IPAnswer
	Resolvers []model.DNSResolverInfo
	Err       error
}

type Options struct {
	Timeout      time.Duration
	Servers      []string
	DoHServers   []string
	FilterFakeIP bool
}

var DefaultServers = []string{
	"1.1.1.1",
	"1.0.0.1",
	"8.8.8.8",
	"8.8.4.4",
	"180.184.1.1",
	"180.184.2.2",
	"2606:4700:4700::1111",
	"2606:4700:4700::1001",
	"2001:4860:4860::8888",
	"2001:4860:4860::8844",
}

var DefaultDoHServers = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
	"https://doh.pub/dns-query",
	"https://dns.alidns.com/dns-query",
}

func Apply(ctx context.Context, result *model.LookupResult, timeout time.Duration) {
	ApplyWithOptions(ctx, result, Options{
		Timeout:      timeout,
		Servers:      DefaultServers,
		DoHServers:   DefaultDoHServers,
		FilterFakeIP: true,
	})
}

func ApplyWithOptions(ctx context.Context, result *model.LookupResult, opts Options) {
	resolver := NewPublicMultiResolver(opts.Servers, opts.Timeout)
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ApplyWithResolverOptions(ctx, result, opts, resolver)
}

func ApplyWithResolver(ctx context.Context, result *model.LookupResult, timeout time.Duration, resolver Resolver) {
	ApplyWithResolverOptions(ctx, result, Options{Timeout: timeout}, resolver)
}

func ApplyWithResolverOptions(ctx context.Context, result *model.LookupResult, opts Options, resolver Resolver) {
	if result == nil || result.Type != model.QueryDomain || result.NormalizedQuery == "" || resolver == nil {
		return
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	start := time.Now()

	host := strings.TrimSuffix(result.NormalizedQuery, ".")
	info := &model.DNSInfo{}
	recorder := dnsResolverRecorder{}
	resolvers := resolversForSampling(resolver)

	var heldFakeAddrs heldFakeIPAddrs
	udpCtx, cancelUDP := context.WithTimeout(ctx, opts.Timeout)
	for _, sample := range sampleResolvers(udpCtx, host, resolvers) {
		recorder.recordResolverSample(sample)
		mergeResolverSample(info, &heldFakeAddrs, sample, opts.FilterFakeIP)
	}
	cancelUDP()

	dohCtx, cancelDoH := context.WithTimeout(ctx, opts.Timeout)
	dohResult := lookupDoHIP(dohCtx, host, opts.DoHServers, opts.Timeout)
	cancelDoH()
	if dohResult.Err == nil {
		heldFakeAddrs.merge(appendIPAddrs(info, dohResult.A, opts.FilterFakeIP))
		heldFakeAddrs.merge(appendIPAddrs(info, dohResult.AAAA, opts.FilterFakeIP))
		recorder.recordResolvers(dohResult.Resolvers)
	} else if len(opts.DoHServers) > 0 {
		recorder.recordResolvers(dohResult.Resolvers)
		result.Meta.Warnings = append(result.Meta.Warnings, "DNS DoH fallback failed: "+dohResult.Err.Error())
	}
	reconcileHeldFakeIPAddrs(result, info, heldFakeAddrs)
	sortAddresses(info.A)
	sortAddresses(info.AAAA)
	sortMX(info.MX)
	sort.Strings(info.NS)
	applyNSComparison(result, info)

	info.Resolvers = recorder.list()
	info.ElapsedMs = time.Since(start).Milliseconds()
	if len(info.A) == 0 && len(info.AAAA) == 0 && info.CNAME == "" && len(info.MX) == 0 && len(info.NS) == 0 {
		result.Meta.Warnings = append(result.Meta.Warnings, "DNS enrichment returned no records")
		return
	}
	result.Enrichment.DNS = info
}

func applyNSComparison(result *model.LookupResult, info *model.DNSInfo) {
	info.RegistryNS = normalizeResultNameservers(result.Nameservers)
	if len(info.RegistryNS) == 0 || len(info.NS) == 0 {
		return
	}
	if !sameStringSet(info.RegistryNS, info.NS) {
		info.NSMismatch = true
		result.Meta.Warnings = append(result.Meta.Warnings, "Registry/WHOIS nameservers differ from live DNS NS records; this can happen after recent NS changes or resolver cache lag")
	}
}

func normalizeResultNameservers(values []model.Nameserver) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		host := normalizeNSHost(value.Host)
		if host != "" && !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeNSHost(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func sortAddresses(values []model.DNSAddress) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].IP < values[j].IP
	})
}

type resolverSample struct {
	Resolver Resolver
	CNAME    string
	Addrs    []net.IPAddr
	MX       []*net.MX
	NS       []*net.NS
}

func sampleResolvers(ctx context.Context, host string, resolvers []Resolver) []resolverSample {
	var wg sync.WaitGroup
	out := make(chan resolverSample, len(resolvers))
	for _, resolver := range resolvers {
		wg.Add(1)
		go func(current Resolver) {
			defer wg.Done()
			sample := resolverSample{Resolver: current}
			if cname, err := current.LookupCNAME(ctx, host); err == nil {
				sample.CNAME = cname
			}
			if addrs, err := current.LookupIPAddr(ctx, host); err == nil {
				sample.Addrs = addrs
			}
			if records, err := current.LookupMX(ctx, host); err == nil {
				sample.MX = records
			}
			if records, err := current.LookupNS(ctx, host); err == nil {
				sample.NS = records
			}
			out <- sample
		}(resolver)
	}
	wg.Wait()
	close(out)

	samples := make([]resolverSample, 0, len(resolvers))
	for sample := range out {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		return resolverLabel(samples[i].Resolver) < resolverLabel(samples[j].Resolver)
	})
	return samples
}

func mergeResolverSample(info *model.DNSInfo, held *heldFakeIPAddrs, sample resolverSample, filterFakeIP bool) {
	if sample.CNAME != "" && info.CNAME == "" {
		info.CNAME = strings.ToLower(strings.TrimSuffix(sample.CNAME, "."))
	}
	if len(sample.Addrs) > 0 {
		held.merge(appendIPAddrs(info, ipAnswersFromResolver(sample.Addrs, sample.Resolver), filterFakeIP))
	}
	if len(sample.MX) > 0 {
		for _, record := range sample.MX {
			if record != nil {
				appendDNSMX(info, record)
			}
		}
	}
	if len(sample.NS) > 0 {
		for _, record := range sample.NS {
			if record == nil {
				continue
			}
			name := strings.ToLower(strings.TrimSuffix(record.Host, "."))
			if name != "" && !hasString(info.NS, name) {
				info.NS = append(info.NS, name)
			}
		}
	}
}

func resolversForSampling(resolver Resolver) []Resolver {
	if multi, ok := resolver.(MultiResolver); ok {
		resolvers := multi.Resolvers()
		if len(resolvers) > 0 {
			return resolvers
		}
	}
	return []Resolver{resolver}
}

func resolverLabel(resolver Resolver) string {
	if named, ok := resolver.(interface{ Label() string }); ok {
		return named.Label()
	}
	return "system"
}

func appendDNSMX(info *model.DNSInfo, record *net.MX) {
	host := strings.ToLower(strings.TrimSuffix(record.Host, "."))
	if host == "" {
		return
	}
	for _, existing := range info.MX {
		if existing.Host == host && existing.Pref == record.Pref {
			return
		}
	}
	info.MX = append(info.MX, model.DNSMX{
		Host: host,
		Pref: record.Pref,
	})
}

func sortMX(values []model.DNSMX) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Pref == values[j].Pref {
			return values[i].Host < values[j].Host
		}
		return values[i].Pref < values[j].Pref
	})
}

type dnsResolverRecorder struct {
	seen   map[string]bool
	listed []model.DNSResolverInfo
}

func (r *dnsResolverRecorder) recordResolverSample(sample resolverSample) {
	status := "empty"
	if sample.CNAME != "" || len(sample.Addrs) > 0 || len(sample.MX) > 0 || len(sample.NS) > 0 {
		status = "ok"
	}
	r.record(model.DNSResolverInfo{
		Source:   "udp",
		Resolver: resolverLabel(sample.Resolver),
		Status:   status,
	})
}

func (r *dnsResolverRecorder) recordResolvers(resolvers []model.DNSResolverInfo) {
	for _, resolver := range resolvers {
		r.record(resolver)
	}
}

func (r *dnsResolverRecorder) record(info model.DNSResolverInfo) {
	if info.Source == "" && info.Resolver == "" {
		return
	}
	if info.Source == "" {
		info.Source = "system"
	}
	key := info.Source + "\x00" + info.Resolver + "\x00" + info.Endpoint
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.listed = append(r.listed, info)
}

func (r *dnsResolverRecorder) list() []model.DNSResolverInfo {
	return r.listed
}

type heldFakeIPAddrs struct {
	A    []IPAnswer
	AAAA []IPAnswer
}

func (h *heldFakeIPAddrs) merge(other heldFakeIPAddrs) {
	h.A = append(h.A, other.A...)
	h.AAAA = append(h.AAAA, other.AAAA...)
}

func appendIPAddrs(info *model.DNSInfo, answers []IPAnswer, filterFakeIP bool) heldFakeIPAddrs {
	var held heldFakeIPAddrs
	for _, answer := range answers {
		if answer.Addr.IP == nil {
			continue
		}
		if filterFakeIP && isFakeIP(answer.Addr.IP) {
			if answer.Addr.IP.To4() != nil {
				held.A = append(held.A, answer)
			} else {
				held.AAAA = append(held.AAAA, answer)
			}
			continue
		}
		appendDNSAddress(info, answer)
	}
	return held
}

func reconcileHeldFakeIPAddrs(result *model.LookupResult, info *model.DNSInfo, held heldFakeIPAddrs) {
	reconcileHeldFakeIPFamily(result, &info.A, held.A, "A")
	reconcileHeldFakeIPFamily(result, &info.AAAA, held.AAAA, "AAAA")
}

func reconcileHeldFakeIPFamily(result *model.LookupResult, values *[]model.DNSAddress, held []IPAnswer, family string) {
	if len(held) == 0 {
		return
	}
	warnFakeIPAddrs(result, held, family, len(*values) > 0)
	if len(*values) > 0 {
		return
	}
	for _, answer := range held {
		appendDNSAddressToFamily(values, answer)
	}
}

func warnFakeIPAddrs(result *model.LookupResult, held []IPAnswer, family string, replacementAvailable bool) {
	counts := map[string]int{}
	for _, answer := range held {
		if answer.Addr.IP == nil {
			continue
		}
		counts[answer.Addr.IP.String()]++
	}
	ips := make([]string, 0, len(counts))
	for ip := range counts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		count := counts[ip]
		seen := ""
		if count > 1 {
			seen = fmt.Sprintf(" seen from %d resolvers; likely local fake-IP/TUN interception", count)
		}
		if replacementAvailable {
			result.Meta.Warnings = append(result.Meta.Warnings, "DNS enrichment ignored reserved 198.18/15 "+family+" answer "+ip+seen+" because a non-reserved answer was available")
			continue
		}
		result.Meta.Warnings = append(result.Meta.Warnings, "DNS enrichment kept reserved 198.18/15 "+family+" answer "+ip+seen+" because no non-reserved replacement was available")
	}
}

func appendDNSAddress(info *model.DNSInfo, answer IPAnswer) {
	if answer.Addr.IP.To4() != nil {
		appendDNSAddressToFamily(&info.A, answer)
		return
	}
	appendDNSAddressToFamily(&info.AAAA, answer)
}

func appendDNSAddressToFamily(values *[]model.DNSAddress, answer IPAnswer) {
	value := model.DNSAddress{
		IP:       answer.Addr.IP.String(),
		Source:   answer.Source,
		Resolver: answer.Resolver,
		Endpoint: answer.Endpoint,
	}
	if answer.Addr.IP.To4() != nil {
		value.Version = "ipv4"
	} else {
		value.Version = "ipv6"
	}
	for index := range *values {
		if (*values)[index].IP != value.IP {
			continue
		}
		(*values)[index].Source = mergeLabel((*values)[index].Source, value.Source)
		(*values)[index].Resolver = mergeLabel((*values)[index].Resolver, value.Resolver)
		(*values)[index].Endpoint = mergeLabel((*values)[index].Endpoint, value.Endpoint)
		return
	}
	*values = append(*values, value)
}

func ipAnswersFromResolver(addrs []net.IPAddr, resolver Resolver) []IPAnswer {
	label := resolverLabel(resolver)
	answers := make([]IPAnswer, 0, len(addrs))
	for _, addr := range addrs {
		answers = append(answers, IPAnswer{
			Addr:     addr,
			Source:   "udp",
			Resolver: label,
		})
	}
	return answers
}

func hasDNSAddress(values []model.DNSAddress, ip string) bool {
	for _, value := range values {
		if value.IP == ip {
			return true
		}
	}
	return false
}

func mergeLabel(current, incoming string) string {
	if incoming == "" || current == incoming {
		return current
	}
	if current == "" {
		return incoming
	}
	parts := strings.Split(current, ", ")
	for _, part := range parts {
		if part == incoming {
			return current
		}
	}
	return current + ", " + incoming
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type publicResolver struct {
	resolver *net.Resolver
	label    string
}

type multiResolver struct {
	resolvers []publicResolver
}

type fallbackResolver struct {
	resolvers []publicResolver
	lastLabel string
}

func NewPublicMultiResolver(servers []string, timeout time.Duration) Resolver {
	resolvers := newPublicResolvers(servers, timeout)
	if len(resolvers) == 0 {
		return nil
	}
	if len(resolvers) == 1 {
		return resolvers[0]
	}
	return multiResolver{resolvers: resolvers}
}

func NewPublicResolver(servers []string, timeout time.Duration) Resolver {
	resolvers := newPublicResolvers(servers, timeout)
	if len(resolvers) == 0 {
		return nil
	}
	if len(resolvers) == 1 {
		return resolvers[0]
	}
	return &fallbackResolver{resolvers: resolvers}
}

func newPublicResolvers(servers []string, timeout time.Duration) []publicResolver {
	servers = normalizeServers(servers)
	if len(servers) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	resolvers := make([]publicResolver, 0, len(servers))
	for _, server := range servers {
		resolvers = append(resolvers, newSingleServerResolver(server, timeout))
	}
	return resolvers
}

func newSingleServerResolver(server string, timeout time.Duration) publicResolver {
	dialer := &net.Dialer{Timeout: timeout}
	return publicResolver{resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return dialer.DialContext(dialCtx, network, server)
		},
	}, label: dnsServerLabel(server)}
}

func (r publicResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return r.resolver.LookupIPAddr(ctx, host)
}

func (r publicResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r.resolver.LookupCNAME(ctx, host)
}

func (r publicResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, host)
}

func (r publicResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return r.resolver.LookupNS(ctx, host)
}

func (r publicResolver) Label() string {
	return r.label
}

func (r multiResolver) Resolvers() []Resolver {
	out := make([]Resolver, 0, len(r.resolvers))
	for _, resolver := range r.resolvers {
		out = append(out, resolver)
	}
	return out
}

func (r multiResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	fallback := fallbackResolver{resolvers: r.resolvers}
	return fallback.LookupIPAddr(ctx, host)
}

func (r multiResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	fallback := fallbackResolver{resolvers: r.resolvers}
	return fallback.LookupCNAME(ctx, host)
}

func (r multiResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	fallback := fallbackResolver{resolvers: r.resolvers}
	return fallback.LookupMX(ctx, host)
}

func (r multiResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	fallback := fallbackResolver{resolvers: r.resolvers}
	return fallback.LookupNS(ctx, host)
}

func (r multiResolver) Label() string {
	if len(r.resolvers) > 0 {
		return r.resolvers[0].label
	}
	return ""
}

func (r *fallbackResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	var lastErr error
	for _, resolver := range r.resolvers {
		records, err := resolver.LookupIPAddr(ctx, host)
		if err == nil {
			r.lastLabel = resolver.label
			return records, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *fallbackResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	var lastErr error
	for _, resolver := range r.resolvers {
		record, err := resolver.LookupCNAME(ctx, host)
		if err == nil {
			r.lastLabel = resolver.label
			return record, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (r *fallbackResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	var lastErr error
	for _, resolver := range r.resolvers {
		records, err := resolver.LookupMX(ctx, host)
		if err == nil {
			r.lastLabel = resolver.label
			return records, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *fallbackResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	var lastErr error
	for _, resolver := range r.resolvers {
		records, err := resolver.LookupNS(ctx, host)
		if err == nil {
			r.lastLabel = resolver.label
			return records, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *fallbackResolver) Label() string {
	if r.lastLabel != "" {
		return r.lastLabel
	}
	if len(r.resolvers) > 0 {
		return r.resolvers[0].label
	}
	return ""
}

func normalizeServers(values []string) []string {
	seen := map[string]bool{}
	var servers []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			host = strings.Trim(value, "[]")
			port = "53"
		}
		if net.ParseIP(host) == nil {
			continue
		}
		server := net.JoinHostPort(host, port)
		if !seen[server] {
			seen[server] = true
			servers = append(servers, server)
		}
	}
	return servers
}

func dnsServerLabel(server string) string {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return server
	}
	if port == "53" {
		return strings.Trim(host, "[]")
	}
	return server
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type dohResolverResult struct {
	Index int
	A     []net.IPAddr
	AAAA  []net.IPAddr
	Info  model.DNSResolverInfo
	Err   error
}

func lookupDoHIP(ctx context.Context, host string, resolvers []string, timeout time.Duration) dohLookupResult {
	resolvers = normalizeDoHResolvers(resolvers)
	if len(resolvers) == 0 {
		return dohLookupResult{Err: errors.New("no DoH resolvers configured")}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var lastErr error
	var failedResolvers []string
	var outA []IPAnswer
	var outAAAA []IPAnswer
	infos := make([]model.DNSResolverInfo, 0, len(resolvers))
	results := make(chan dohResolverResult, len(resolvers))
	var wg sync.WaitGroup
	for index, resolver := range resolvers {
		wg.Add(1)
		go func(index int, resolver string) {
			defer wg.Done()
			results <- lookupDoHResolver(ctx, host, resolver, timeout, index)
		}(index, resolver)
	}
	wg.Wait()
	close(results)

	ordered := make([]dohResolverResult, len(resolvers))
	for result := range results {
		ordered[result.Index] = result
	}
	for _, result := range ordered {
		label := result.Info.Resolver
		resolver := result.Info.Endpoint
		if result.Err == nil {
			outA = append(outA, ipAnswersFromDoH(result.A, label, resolver)...)
			outAAAA = append(outAAAA, ipAnswersFromDoH(result.AAAA, label, resolver)...)
		} else {
			lastErr = result.Err
			failedResolvers = append(failedResolvers, label+": "+result.Info.Error)
		}
		infos = append(infos, result.Info)
	}
	if len(outA) > 0 || len(outAAAA) > 0 {
		return dohLookupResult{A: outA, AAAA: outAAAA, Resolvers: infos}
	}
	if len(failedResolvers) > 0 {
		return dohLookupResult{Resolvers: infos, Err: summarizeDoHErrors(len(resolvers), failedResolvers)}
	}
	return dohLookupResult{Resolvers: infos, Err: lastErr}
}

func summarizeDoHErrors(total int, failures []string) error {
	if len(failures) == 0 {
		return errors.New("all configured DoH resolvers returned no records")
	}
	if len(failures) == total {
		return fmt.Errorf("all %d configured DoH resolvers failed; first: %s", total, failures[0])
	}
	return fmt.Errorf("%d of %d configured DoH resolvers failed; first: %s", len(failures), total, failures[0])
}

func lookupDoHResolver(ctx context.Context, host, resolver string, timeout time.Duration, index int) dohResolverResult {
	label := dohResolverLabel(resolver)
	info := model.DNSResolverInfo{
		Source:   "doh",
		Resolver: label,
		Endpoint: resolver,
		Status:   "empty",
	}
	resolverCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var a []net.IPAddr
	var aaaa []net.IPAddr
	var errA error
	var errAAAA error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		a, errA = queryDoH(resolverCtx, resolver, host, "A")
	}()
	go func() {
		defer wg.Done()
		aaaa, errAAAA = queryDoH(resolverCtx, resolver, host, "AAAA")
	}()
	wg.Wait()

	result := dohResolverResult{
		Index: index,
		A:     a,
		AAAA:  aaaa,
		Info:  info,
	}
	if errA != nil && errAAAA != nil {
		info.Status = "error"
		info.Error = fmt.Sprintf("A: %v; AAAA: %v", errA, errAAAA)
		result.Info = info
		result.Err = fmt.Errorf("%s: %s", resolver, info.Error)
		return result
	}
	if len(a) > 0 || len(aaaa) > 0 {
		info.Status = "ok"
	}
	result.Info = info
	return result
}

func ipAnswersFromDoH(addrs []net.IPAddr, resolver, endpoint string) []IPAnswer {
	answers := make([]IPAnswer, 0, len(addrs))
	for _, addr := range addrs {
		answers = append(answers, IPAnswer{
			Addr:     addr,
			Source:   "doh",
			Resolver: resolver,
			Endpoint: endpoint,
		})
	}
	return answers
}

func dohResolverLabel(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return endpoint
	}
	return parsed.Hostname()
}

func queryDoH(ctx context.Context, endpoint, host, recordType string) ([]net.IPAddr, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid DoH endpoint")
	}
	if addrs, err := queryDoHJSON(ctx, *parsed, host, recordType); err == nil {
		return addrs, nil
	}
	return queryDoHMessage(ctx, *parsed, host, recordType)
}

func queryDoHJSON(ctx context.Context, parsed url.URL, host, recordType string) ([]net.IPAddr, error) {
	values := parsed.Query()
	values.Set("name", host)
	values.Set("type", recordType)
	parsed.RawQuery = values.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client, cleanup := dohHTTPClient(parsed)
	defer cleanup()
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var payload dohResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Status != 0 {
		return nil, fmt.Errorf("DNS status %d", payload.Status)
	}
	wantType := 1
	if strings.EqualFold(recordType, "AAAA") {
		wantType = 28
	}
	var addrs []net.IPAddr
	for _, answer := range payload.Answer {
		if answer.Type != wantType {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(answer.Data))
		if ip != nil {
			addrs = append(addrs, net.IPAddr{IP: ip})
		}
	}
	return addrs, nil
}

func queryDoHMessage(ctx context.Context, parsed url.URL, host, recordType string) ([]net.IPAddr, error) {
	query, err := buildDNSQuery(host, recordType)
	if err != nil {
		return nil, err
	}
	values := parsed.Query()
	values.Set("dns", query)
	parsed.RawQuery = values.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	client, cleanup := dohHTTPClient(parsed)
	defer cleanup()
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseDNSMessageAddrs(body, recordType)
}

func dohHTTPClient(parsed url.URL) (*http.Client, func()) {
	ips := dohBootstrapIPs(parsed.Hostname())
	if len(ips) == 0 {
		return http.DefaultClient, func() {}
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	fallbackDialer := &net.Dialer{Timeout: 5 * time.Second}
	bootstrapDialer := &net.Dialer{Timeout: dohBootstrapDialTimeout}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialDoHAddress(ctx, network, address, parsed.Hostname(), port, ips, bootstrapDialer.DialContext, fallbackDialer.DialContext)
	}
	client := &http.Client{Transport: transport}
	return client, transport.CloseIdleConnections
}

const dohBootstrapDialTimeout = 600 * time.Millisecond

type dohDialFunc func(context.Context, string, string) (net.Conn, error)

func dialDoHAddress(ctx context.Context, network, address, hostname, defaultPort string, ips []string, bootstrapDial, fallbackDial dohDialFunc) (net.Conn, error) {
	host, dialPort, err := net.SplitHostPort(address)
	if err != nil || !sameDNSHostname(host, hostname) || len(ips) == 0 {
		return fallbackDial(ctx, network, address)
	}
	if dialPort == "" {
		dialPort = defaultPort
	}
	if dialPort == "" {
		dialPort = "443"
	}

	ipv4, ipv6 := splitBootstrapIPs(ips)
	var failures []string
	if conn, ok := dialDoHBootstrapList(ctx, network, dialPort, ipv4, bootstrapDial, &failures); ok {
		return conn, nil
	}
	if conn, err := fallbackDial(ctx, network, address); err == nil {
		return conn, nil
	} else {
		failures = append(failures, "hostname "+address+": "+err.Error())
	}
	if conn, ok := dialDoHBootstrapList(ctx, network, dialPort, ipv6, bootstrapDial, &failures); ok {
		return conn, nil
	}
	return nil, fmt.Errorf("DoH bootstrap and hostname fallback failed: %s", strings.Join(failures, "; "))
}

func dialDoHBootstrapList(ctx context.Context, network, port string, ips []string, dial dohDialFunc, failures *[]string) (net.Conn, bool) {
	for _, ip := range ips {
		attemptCtx, cancel := context.WithTimeout(ctx, dohBootstrapAttemptTimeout(ctx))
		conn, err := dial(attemptCtx, network, net.JoinHostPort(ip, port))
		cancel()
		if err == nil {
			return conn, true
		}
		*failures = append(*failures, ip+": "+err.Error())
		if ctx.Err() != nil {
			return nil, false
		}
	}
	return nil, false
}

func dohBootstrapAttemptTimeout(ctx context.Context) time.Duration {
	timeout := dohBootstrapDialTimeout
	deadline, ok := ctx.Deadline()
	if !ok {
		return timeout
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Nanosecond
	}
	reserved := remaining / 3
	if reserved > 0 && reserved < timeout {
		timeout = reserved
	}
	if timeout < 50*time.Millisecond && remaining > 50*time.Millisecond {
		return 50 * time.Millisecond
	}
	return timeout
}

func splitBootstrapIPs(ips []string) ([]string, []string) {
	var ipv4 []string
	var ipv6 []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}
	return ipv4, ipv6
}

func sameDNSHostname(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func dohBootstrapIPs(host string) []string {
	switch strings.ToLower(strings.TrimSuffix(host, ".")) {
	case "cloudflare-dns.com":
		return []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}
	case "dns.google":
		return []string{"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"}
	case "doh.pub":
		return []string{"1.12.12.12", "120.53.53.53"}
	case "dns.alidns.com":
		return []string{"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"}
	default:
		return nil
	}
}

func buildDNSQuery(host, recordType string) (string, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return "", err
	}
	qtype := dnsmessage.TypeA
	if strings.EqualFold(recordType, "AAAA") {
		qtype = dnsmessage.TypeAAAA
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               0,
		RecursionDesired: true,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return "", err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return "", err
	}
	msg, err := builder.Finish()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(msg), nil
}

func parseDNSMessageAddrs(body []byte, recordType string) ([]net.IPAddr, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(body)
	if err != nil {
		return nil, err
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS status %d", header.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var addrs []net.IPAddr
	for {
		answer, err := parser.Answer()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if strings.EqualFold(recordType, "A") {
				addrs = append(addrs, net.IPAddr{IP: net.IPv4(body.A[0], body.A[1], body.A[2], body.A[3])})
			}
		case *dnsmessage.AAAAResource:
			if strings.EqualFold(recordType, "AAAA") {
				addrs = append(addrs, net.IPAddr{IP: net.IP(body.AAAA[:])})
			}
		}
	}
	return addrs, nil
}

func normalizeDoHResolvers(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			continue
		}
		normalized := parsed.String()
		if !seen[normalized] {
			seen[normalized] = true
			out = append(out, normalized)
		}
	}
	return out
}

func isFakeIP(ip net.IP) bool {
	addr, ok := netipFromIP(ip)
	if !ok {
		return false
	}
	fakeRange := netipMustPrefix("198.18.0.0/15")
	return fakeRange.Contains(addr)
}

func netipFromIP(ip net.IP) (netip.Addr, bool) {
	if parsed, ok := netip.AddrFromSlice(ip); ok {
		return parsed.Unmap(), true
	}
	return netip.Addr{}, false
}

func netipMustPrefix(value string) netip.Prefix {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		panic(err)
	}
	return prefix
}
