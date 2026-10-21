// Package delegation infers a domain's registration status from DNS when its
// registry offers no usable WHOIS or RDAP service. It asks the parent zone's
// authoritative nameservers directly (no recursion): a delegation means the
// name is registered, NXDOMAIN means the registry has no such name.
package delegation

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxServers      = 6
	nsLookupTimeout = 1500 * time.Millisecond
	maxReferrals    = 3
	perQueryTimeout = 2 * time.Second
)

// Exchange sends one DNS message to server ("ip:53") and returns the reply.
type Exchange func(ctx context.Context, server string, query []byte) ([]byte, error)

type Checker struct {
	LookupNS   func(ctx context.Context, name string) ([]*net.NS, error)
	LookupHost func(ctx context.Context, host string) ([]string, error)
	Exchange   Exchange
}

func New() Checker {
	return Checker{
		LookupNS:   net.DefaultResolver.LookupNS,
		LookupHost: net.DefaultResolver.LookupHost,
		Exchange:   exchange,
	}
}

type Result struct {
	Domain      string
	Zone        string
	Server      string
	Status      model.ResultStatus
	Nameservers []string
	Body        string
	// Wildcard is set when the "not registered" verdict rests on the zone
	// answering every name the same way.
	Wildcard bool
}

// Check looks up the delegation of domain in its parent zone.
func (c Checker) Check(ctx context.Context, domain string) (*Result, error) {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("delegation check needs a domain below a TLD, got %q", domain)
	}
	zone, hosts, err := c.parentZone(ctx, domain)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for hop := 0; hop <= maxReferrals; hop++ {
		reply, server, err := c.ask(ctx, domain, hosts)
		if err != nil {
			return nil, fmt.Errorf("query %s nameservers: %w", zone, err)
		}
		result, next, nextHosts := interpret(domain, zone, server, reply)
		if result != nil && result.Status == model.StatusUnknown {
			c.resolveWildcard(ctx, result, domain, hosts)
		}
		if result != nil {
			return result, nil
		}
		// A referral to a zone between the parent and the domain (for
		// example uy → com.uy): follow it.
		zone, hosts = next, nextHosts
		lastErr = fmt.Errorf("referral loop below %s", zone)
	}
	return nil, lastErr
}

// resolveWildcard handles a "name exists, no delegation" answer. Zones
// with a wildcard (*.com.ph points every name at a parking page) answer
// that way for every name, registered or not. If a random sibling gets the
// same answer the zone is a wildcard, and since registered names are always
// delegated, no delegation means the name is not registered.
func (c Checker) resolveWildcard(ctx context.Context, result *Result, domain string, hosts []string) {
	parent := domain[strings.Index(domain, ".")+1:]
	probe := fmt.Sprintf("whoice-probe-%08x.%s", rand.Uint32(), parent)
	reply, _, err := c.ask(ctx, probe, hosts)
	if err != nil || reply.RCode != dnsmessage.RCodeSuccess {
		return
	}
	if probeResult, _, _ := interpret(probe, result.Zone, "", reply); probeResult == nil || probeResult.Status != model.StatusUnknown {
		return
	}
	result.Status = model.StatusUnregistered
	result.Wildcard = true
	result.Body += fmt.Sprintf("\n; Wildcard zone: the random name %s gets the same answer, so the\n; missing delegation means %s is most likely available.\n", probe, domain)
}

func (c Checker) parentZone(ctx context.Context, domain string) (string, []string, error) {
	labels := strings.Split(domain, ".")
	for i := 1; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		records, err := c.LookupNS(ctx, zone+".")
		if err != nil || len(records) == 0 {
			if ctx.Err() != nil {
				return "", nil, ctx.Err()
			}
			continue
		}
		hosts := make([]string, 0, len(records))
		for _, record := range records {
			if host := strings.TrimSuffix(strings.ToLower(record.Host), "."); host != "" {
				hosts = append(hosts, host)
			}
		}
		if len(hosts) > 0 {
			return zone, hosts, nil
		}
	}
	return "", nil, fmt.Errorf("no nameservers found for the parent zone of %s", domain)
}

type reply struct {
	msg    dnsmessage.Message
	server string
}

// ask queries up to maxServers of the zone's nameservers in random order and
// returns the first authoritative reply.
func (c Checker) ask(ctx context.Context, domain string, hosts []string) (*dnsmessage.Message, string, error) {
	hosts = append([]string(nil), hosts...)
	rand.Shuffle(len(hosts), func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })
	if len(hosts) > maxServers {
		hosts = hosts[:maxServers]
	}
	query, id, err := buildQuery(domain)
	if err != nil {
		return nil, "", err
	}
	// Resolve every nameserver at once and query them in the order they
	// resolve: some registries list nameservers that do not resolve or
	// time out (.kh), which must not use up the budget for the good ones.
	type resolved struct {
		host  string
		addrs []string
		err   error
	}
	results := make(chan resolved, len(hosts))
	for _, host := range hosts {
		go func(host string) {
			lookupCtx, cancel := context.WithTimeout(ctx, nsLookupTimeout)
			defer cancel()
			addrs, err := c.lookupHostRetry(lookupCtx, host)
			results <- resolved{host: host, addrs: addrs, err: err}
		}(host)
	}
	var errs []string
	for range hosts {
		item := <-results
		if item.err != nil || len(item.addrs) == 0 {
			reason := "no address"
			if item.err != nil {
				reason = "no address (" + item.err.Error() + ")"
			}
			errs = append(errs, item.host+": "+reason)
			continue
		}
		addr := preferIPv4(item.addrs)
		tryCtx, cancel := context.WithTimeout(ctx, perQueryTimeout)
		body, err := c.Exchange(tryCtx, net.JoinHostPort(addr, "53"), query)
		cancel()
		if err != nil {
			errs = append(errs, item.host+": "+err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(body); err != nil || msg.ID != id {
			errs = append(errs, item.host+": malformed reply")
			continue
		}
		if msg.RCode != dnsmessage.RCodeSuccess && msg.RCode != dnsmessage.RCodeNameError {
			errs = append(errs, item.host+": "+msg.RCode.String())
			continue
		}
		return &msg, fmt.Sprintf("%s (%s)", item.host, addr), nil
	}
	if len(errs) == 0 {
		return nil, "", errors.New("no nameservers to query")
	}
	return nil, "", errors.New(strings.Join(errs, "; "))
}

// interpret turns a reply into a result, or into a referral to follow.
func interpret(domain, zone, server string, msg *dnsmessage.Message) (*Result, string, []string) {
	result := &Result{Domain: domain, Zone: zone, Server: server, Status: model.StatusUnknown}
	var nameservers []string
	var referralZone string
	var referralHosts []string
	for _, section := range [][]dnsmessage.Resource{msg.Answers, msg.Authorities} {
		for _, rr := range section {
			ns, ok := rr.Body.(*dnsmessage.NSResource)
			if !ok {
				continue
			}
			owner := canonical(rr.Header.Name.String())
			host := canonical(ns.NS.String())
			switch {
			case owner == domain:
				nameservers = appendUnique(nameservers, host)
			case strings.HasSuffix(domain, "."+owner) && strings.HasSuffix(owner, "."+zone):
				referralZone = owner
				referralHosts = appendUnique(referralHosts, host)
			}
		}
	}
	switch {
	case msg.RCode == dnsmessage.RCodeNameError:
		result.Status = model.StatusUnregistered
	case len(nameservers) > 0:
		sort.Strings(nameservers)
		result.Status = model.StatusRegistered
		result.Nameservers = nameservers
	case referralZone != "":
		return nil, referralZone, referralHosts
	}
	result.Body = render(result, msg)
	return result, "", nil
}

func render(result *Result, msg *dnsmessage.Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "; DNS delegation check for %s\n", result.Domain)
	fmt.Fprintf(&b, "; Asked the authoritative nameservers of %s. without recursion,\n", result.Zone)
	b.WriteString("; because the registry publishes no usable WHOIS or RDAP service.\n")
	fmt.Fprintf(&b, "; Server: %s\n", result.Server)
	status := "NOERROR"
	if msg.RCode == dnsmessage.RCodeNameError {
		status = "NXDOMAIN"
	}
	fmt.Fprintf(&b, "; Reply: %s, %d answer, %d authority\n", status, len(msg.Answers), len(msg.Authorities))
	switch result.Status {
	case model.StatusRegistered:
		b.WriteString("; Conclusion: delegated, so the name is registered\n")
	case model.StatusUnregistered:
		b.WriteString("; Conclusion: the registry zone has no such name, so it is most likely available\n")
	default:
		b.WriteString("; Conclusion: the name exists but has no delegation; status unknown\n")
	}
	for _, section := range []struct {
		name    string
		records []dnsmessage.Resource
	}{{"ANSWER", msg.Answers}, {"AUTHORITY", msg.Authorities}} {
		if len(section.records) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n;; %s SECTION:\n", section.name)
		for _, rr := range section.records {
			fmt.Fprintf(&b, "%s\t%d\tIN\t%s\n", rr.Header.Name.String(), rr.Header.TTL, recordText(rr.Body))
		}
	}
	return b.String()
}

func recordText(body dnsmessage.ResourceBody) string {
	switch rr := body.(type) {
	case *dnsmessage.NSResource:
		return "NS\t" + rr.NS.String()
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("SOA\t%s %s %d %d %d %d %d", rr.NS.String(), rr.MBox.String(), rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.MinTTL)
	case *dnsmessage.AResource:
		return "A\t" + net.IP(rr.A[:]).String()
	case *dnsmessage.AAAAResource:
		return "AAAA\t" + net.IP(rr.AAAA[:]).String()
	case *dnsmessage.CNAMEResource:
		return "CNAME\t" + rr.CNAME.String()
	default:
		return strings.TrimPrefix(body.GoString(), "dnsmessage.")
	}
}

// lookupHostRetry resolves a nameserver's address, retrying once: under
// concurrent lookups the system resolver occasionally fails transiently.
func (c Checker) lookupHostRetry(ctx context.Context, host string) ([]string, error) {
	addrs, err := c.LookupHost(ctx, host)
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}
	select {
	case <-time.After(150 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return c.LookupHost(ctx, host)
}

func buildQuery(domain string) ([]byte, uint16, error) {
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		return nil, 0, err
	}
	id := uint16(rand.IntN(1 << 16))
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}},
	}
	body, err := msg.Pack()
	return body, id, err
}

// exchange sends the query over UDP and retries over TCP when the reply is
// truncated.
func exchange(ctx context.Context, server string, query []byte) ([]byte, error) {
	body, err := exchangeConn(ctx, "udp", server, query)
	if err != nil {
		return nil, err
	}
	var header dnsmessage.Parser
	if h, err := header.Start(body); err == nil && h.Truncated {
		return exchangeConn(ctx, "tcp", server, query)
	}
	return body, nil
}

func exchangeConn(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if network == "udp" {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func preferIPv4(addrs []string) string {
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			return addr
		}
	}
	return addrs[0]
}

func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
