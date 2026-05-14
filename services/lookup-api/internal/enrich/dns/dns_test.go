package dns

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"golang.org/x/net/dns/dnsmessage"
)

type fakeResolver struct{}

func (fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}}, nil
}

func (fakeResolver) LookupCNAME(context.Context, string) (string, error) {
	return "example.com.", nil
}

func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil
}

func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns1.example.com."}}, nil
}

type fakeIPResolver struct{}

func (fakeIPResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("198.18.0.42")}, {IP: net.ParseIP("93.184.216.34")}}, nil
}

func (fakeIPResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", nil
}

func (fakeIPResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, nil
}

func (fakeIPResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, nil
}

type fakeOnlyResolver struct{}

func (fakeOnlyResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("198.18.0.42")}}, nil
}

func (fakeOnlyResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", nil
}

func (fakeOnlyResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, nil
}

func (fakeOnlyResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, nil
}

type fakeOnlyNamedResolver struct {
	label string
}

func (r fakeOnlyNamedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("198.18.0.42")}}, nil
}

func (fakeOnlyNamedResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", nil
}

func (fakeOnlyNamedResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, nil
}

func (fakeOnlyNamedResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, nil
}

func (r fakeOnlyNamedResolver) Label() string {
	return r.label
}

type staticMultiResolver []Resolver

func (r staticMultiResolver) Resolvers() []Resolver {
	return []Resolver(r)
}

func (r staticMultiResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return r[0].LookupIPAddr(ctx, host)
}

func (r staticMultiResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r[0].LookupCNAME(ctx, host)
}

func (r staticMultiResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return r[0].LookupMX(ctx, host)
}

func (r staticMultiResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return r[0].LookupNS(ctx, host)
}

type slowEmptyResolver struct{}

func (slowEmptyResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return waitForContext(ctx, host)
}

func (slowEmptyResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	_, err := waitForContext(ctx, host)
	return "", err
}

func (slowEmptyResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	_, err := waitForContext(ctx, host)
	return nil, err
}

func (slowEmptyResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	_, err := waitForContext(ctx, host)
	return nil, err
}

func waitForContext(ctx context.Context, _ string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestApplyWithResolver(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	ApplyWithResolver(context.Background(), result, 0, fakeResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if len(result.Enrichment.DNS.A) != 1 || result.Enrichment.DNS.A[0].Version != "ipv4" {
		t.Fatalf("unexpected A records: %+v", result.Enrichment.DNS.A)
	}
	if result.Enrichment.DNS.A[0].Source != "udp" || result.Enrichment.DNS.A[0].Resolver != "system" {
		t.Fatalf("unexpected A resolver label: %+v", result.Enrichment.DNS.A[0])
	}
	if len(result.Enrichment.DNS.Resolvers) != 1 || result.Enrichment.DNS.Resolvers[0].Source != "udp" || result.Enrichment.DNS.Resolvers[0].Resolver != "system" {
		t.Fatalf("unexpected resolver summary: %+v", result.Enrichment.DNS.Resolvers)
	}
	if len(result.Enrichment.DNS.AAAA) != 1 || result.Enrichment.DNS.AAAA[0].Version != "ipv6" {
		t.Fatalf("unexpected AAAA records: %+v", result.Enrichment.DNS.AAAA)
	}
	if result.Enrichment.DNS.CNAME != "example.com" {
		t.Fatalf("unexpected cname %q", result.Enrichment.DNS.CNAME)
	}
	if len(result.Enrichment.DNS.MX) != 1 || result.Enrichment.DNS.MX[0].Host != "mail.example.com" {
		t.Fatalf("unexpected mx: %+v", result.Enrichment.DNS.MX)
	}
	if len(result.Enrichment.DNS.NS) != 1 || result.Enrichment.DNS.NS[0] != "ns1.example.com" {
		t.Fatalf("unexpected ns: %+v", result.Enrichment.DNS.NS)
	}
}

func TestApplyHidesFakeIPAnswersWhenReplacementExists(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	ApplyWithResolverOptions(context.Background(), result, Options{FilterFakeIP: true}, fakeIPResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if len(result.Enrichment.DNS.A) != 1 || result.Enrichment.DNS.A[0].IP != "93.184.216.34" {
		t.Fatalf("unexpected A records: %+v", result.Enrichment.DNS.A)
	}
	if len(result.Meta.Warnings) == 0 {
		t.Fatal("expected reserved IP warning")
	}
}

func TestApplyKeepsFakeIPAnswerWhenNoReplacementExists(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	ApplyWithResolverOptions(context.Background(), result, Options{FilterFakeIP: true}, fakeOnlyResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if len(result.Enrichment.DNS.A) != 1 || result.Enrichment.DNS.A[0].IP != "198.18.0.42" {
		t.Fatalf("unexpected A records: %+v", result.Enrichment.DNS.A)
	}
	if len(result.Meta.Warnings) == 0 {
		t.Fatal("expected reserved IP warning")
	}
}

func TestApplyAggregatesRepeatedFakeIPWarnings(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	resolver := staticMultiResolver{
		fakeOnlyNamedResolver{label: "one"},
		fakeOnlyNamedResolver{label: "two"},
		fakeOnlyNamedResolver{label: "three"},
	}
	ApplyWithResolverOptions(context.Background(), result, Options{FilterFakeIP: true}, resolver)

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if len(result.Meta.Warnings) != 1 {
		t.Fatalf("warnings: %+v", result.Meta.Warnings)
	}
	if !strings.Contains(result.Meta.Warnings[0], "seen from 3 resolvers") {
		t.Fatalf("expected aggregated resolver count, got %q", result.Meta.Warnings[0])
	}
}

func TestApplyFallsBackToDoHAfterFakeIPFilter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "A" {
			http.Error(w, "json disabled for this test", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"type":1,"data":"172.81.100.83"}]}`))
	}))
	t.Cleanup(server.Close)
	oldClient := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = oldClient })

	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	ApplyWithResolverOptions(context.Background(), result, Options{
		DoHServers:   []string{server.URL},
		FilterFakeIP: true,
	}, fakeOnlyResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if len(result.Enrichment.DNS.A) != 1 || result.Enrichment.DNS.A[0].IP != "172.81.100.83" {
		t.Fatalf("unexpected A records: %+v", result.Enrichment.DNS.A)
	}
	if result.Enrichment.DNS.A[0].Source != "doh" || result.Enrichment.DNS.A[0].Resolver == "" {
		t.Fatalf("unexpected A resolver label: %+v", result.Enrichment.DNS.A[0])
	}
	if len(result.Enrichment.DNS.Resolvers) != 2 || result.Enrichment.DNS.Resolvers[1].Source != "doh" {
		t.Fatalf("unexpected resolver summary: %+v", result.Enrichment.DNS.Resolvers)
	}
}

func TestLookupDoHIPQueriesEveryDoHResolver(t *testing.T) {
	first := newJSONDoHTestServer(t, "172.81.100.83")
	second := newJSONDoHTestServer(t, "203.0.113.10")
	oldClient := http.DefaultClient
	http.DefaultClient = first.Client()
	t.Cleanup(func() { http.DefaultClient = oldClient })

	result := lookupDoHIP(context.Background(), "example.com", []string{first.URL, second.URL}, time.Second)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(result.A) != 2 {
		t.Fatalf("expected two DoH answers, got %+v", result.A)
	}
	if result.A[0].Addr.IP.String() != "172.81.100.83" || result.A[1].Addr.IP.String() != "203.0.113.10" {
		t.Fatalf("unexpected DoH answers: %+v", result.A)
	}
	if len(result.Resolvers) != 2 || result.Resolvers[0].Status != "ok" || result.Resolvers[1].Status != "ok" {
		t.Fatalf("unexpected DoH resolver statuses: %+v", result.Resolvers)
	}
}

func TestApplyDoHUsesFreshTimeoutAfterSlowUDP(t *testing.T) {
	server := newJSONDoHTestServer(t, "172.81.100.83")
	oldClient := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = oldClient })

	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
	}
	ApplyWithResolverOptions(context.Background(), result, Options{
		Timeout:      20 * time.Millisecond,
		DoHServers:   []string{server.URL},
		FilterFakeIP: true,
	}, slowEmptyResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment from DoH after UDP timeout")
	}
	if len(result.Enrichment.DNS.A) != 1 || result.Enrichment.DNS.A[0].IP != "172.81.100.83" {
		t.Fatalf("unexpected A records: %+v", result.Enrichment.DNS.A)
	}
	if len(result.Enrichment.DNS.Resolvers) != 2 || result.Enrichment.DNS.Resolvers[1].Status != "ok" {
		t.Fatalf("unexpected resolver summary: %+v", result.Enrichment.DNS.Resolvers)
	}
}

func TestLookupDoHIPIsolatesSlowResolvers(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "slow") {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		if r.URL.Query().Get("type") != "A" {
			w.Header().Set("Content-Type", "application/dns-json")
			_, _ = w.Write([]byte(`{"Status":0}`))
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"type":1,"data":"172.81.100.83"}]}`))
	}))
	t.Cleanup(server.Close)
	oldClient := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = oldClient })

	result := lookupDoHIP(context.Background(), "example.com", []string{server.URL + "/slow", server.URL + "/dns-query"}, 20*time.Millisecond)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(result.A) != 1 || result.A[0].Addr.IP.String() != "172.81.100.83" {
		t.Fatalf("unexpected DoH answers: %+v", result.A)
	}
	if len(result.Resolvers) != 2 {
		t.Fatalf("unexpected resolver summary: %+v", result.Resolvers)
	}
	if result.Resolvers[0].Status != "error" || result.Resolvers[0].Error == "" {
		t.Fatalf("expected slow resolver error, got %+v", result.Resolvers[0])
	}
	if result.Resolvers[1].Status != "ok" {
		t.Fatalf("expected fast resolver ok, got %+v", result.Resolvers[1])
	}
}

func TestApplyWarnsWhenRegistryAndLiveDNSNameserversDiffer(t *testing.T) {
	result := &model.LookupResult{
		NormalizedQuery: "example.com",
		Type:            model.QueryDomain,
		Nameservers:     []model.Nameserver{{Host: "ns-old.example.com."}},
	}
	ApplyWithResolver(context.Background(), result, 0, fakeResolver{})

	if result.Enrichment.DNS == nil {
		t.Fatal("expected DNS enrichment")
	}
	if !result.Enrichment.DNS.NSMismatch {
		t.Fatal("expected NS mismatch")
	}
	if len(result.Enrichment.DNS.RegistryNS) != 1 || result.Enrichment.DNS.RegistryNS[0] != "ns-old.example.com" {
		t.Fatalf("registry ns: %+v", result.Enrichment.DNS.RegistryNS)
	}
	if len(result.Meta.Warnings) == 0 {
		t.Fatal("expected NS mismatch warning")
	}
}

func TestAppendDNSAddressMergesResolverLabelsForSameIP(t *testing.T) {
	info := &model.DNSInfo{}
	appendDNSAddress(info, IPAnswer{
		Addr:     net.IPAddr{IP: net.ParseIP("203.0.113.10")},
		Source:   "doh",
		Resolver: "cloudflare-dns.com",
	})
	appendDNSAddress(info, IPAnswer{
		Addr:     net.IPAddr{IP: net.ParseIP("203.0.113.10")},
		Source:   "doh",
		Resolver: "dns.google",
	})

	if len(info.A) != 1 {
		t.Fatalf("A records: %+v", info.A)
	}
	if info.A[0].Resolver != "cloudflare-dns.com, dns.google" {
		t.Fatalf("resolver label: %+v", info.A[0])
	}
}

func TestQueryDoHMessage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dns") == "" {
			http.Error(w, "missing dns query", http.StatusBadRequest)
			return
		}
		msg := dnsMessageReplyA(t, "example.com.", net.IPv4(172, 81, 100, 83))
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(msg)
	}))
	t.Cleanup(server.Close)
	oldClient := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = oldClient })

	addrs, err := queryDoHMessage(context.Background(), mustParseURL(t, server.URL), "example.com", "A")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "172.81.100.83" {
		t.Fatalf("addrs: %+v", addrs)
	}
}

func TestDoHBootstrapIPsCoverBuiltInResolvers(t *testing.T) {
	tests := map[string]string{
		"cloudflare-dns.com": "1.1.1.1",
		"dns.google":         "8.8.8.8",
		"doh.pub":            "1.12.12.12",
		"dns.alidns.com":     "223.5.5.5",
	}
	for host, want := range tests {
		got := dohBootstrapIPs(host)
		if len(got) == 0 || got[0] != want {
			t.Fatalf("%s bootstrap = %#v, want first %s", host, got, want)
		}
	}
}

func newJSONDoHTestServer(t *testing.T, ip string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "A" {
			w.Header().Set("Content-Type", "application/dns-json")
			_, _ = w.Write([]byte(`{"Status":0}`))
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"type":1,"data":"` + ip + `"}]}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestNormalizeServers(t *testing.T) {
	got := normalizeServers([]string{
		"1.1.1.1",
		"1.1.1.1:53",
		"2606:4700:4700::1111",
		"[2001:4860:4860::8888]:53",
		"not-a-server",
	})
	want := []string{
		"1.1.1.1:53",
		"[2606:4700:4700::1111]:53",
		"[2001:4860:4860::8888]:53",
	}
	if len(got) != len(want) {
		t.Fatalf("servers: got %#v want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("servers: got %#v want %#v", got, want)
		}
	}
}

func mustParseURL(t *testing.T, value string) url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *parsed
}

func TestPublicResolverFallsBackToNextServer(t *testing.T) {
	failing := startTestDNSServer(t, dnsReplyServfail)
	working := startTestDNSServer(t, func(query []byte) []byte {
		return dnsReplyA(query, net.ParseIP("93.184.216.34"))
	})

	resolver := NewPublicResolver([]string{failing, working}, time.Second)
	records, err := resolver.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].IP.String() != "93.184.216.34" {
		t.Fatalf("records: %+v", records)
	}
}

func startTestDNSServer(t *testing.T, reply func([]byte) []byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			response := reply(append([]byte(nil), buffer[:n]...))
			if len(response) > 0 {
				_, _ = conn.WriteTo(response, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func dnsReplyServfail(query []byte) []byte {
	response := append([]byte(nil), query...)
	if len(response) < 12 {
		return nil
	}
	response[2] = 0x81
	response[3] = 0x82
	response[7] = 0
	return response
}

func dnsReplyA(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	questionEnd := dnsQuestionEnd(query)
	if questionEnd <= 12 || questionEnd > len(query) {
		return dnsReplyServfail(query)
	}
	response := make([]byte, 0, questionEnd+16)
	response = append(response, query[:questionEnd]...)
	response[2] = 0x81
	response[3] = 0x80
	response[6] = 0
	response[7] = 1
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
	)
	response = append(response, ip.To4()...)
	return response
}

func dnsMessageReplyA(t *testing.T, host string, ip net.IP) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(host)
	if err != nil {
		t.Fatal(err)
	}
	var a [4]byte
	copy(a[:], ip.To4())
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:           true,
		RecursionDesired:   true,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := builder.AResource(dnsmessage.ResourceHeader{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}, dnsmessage.AResource{A: a}); err != nil {
		t.Fatal(err)
	}
	msg, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func dnsQuestionEnd(query []byte) int {
	offset := 12
	for offset < len(query) {
		length := int(query[offset])
		offset++
		if length == 0 {
			if offset+4 > len(query) {
				return -1
			}
			qtype := binary.BigEndian.Uint16(query[offset : offset+2])
			if qtype != 1 {
				return -1
			}
			return offset + 4
		}
		offset += length
	}
	return -1
}
