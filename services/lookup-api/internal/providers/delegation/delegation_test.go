package delegation

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"golang.org/x/net/dns/dnsmessage"
)

type zoneReply struct {
	rcode       dnsmessage.RCode
	nsOwner     string
	nameservers []string
	soaOwner    string
}

// fakeChecker serves one reply per nameserver host; hosts are resolved to
// fake addresses named after them.
func fakeChecker(t *testing.T, zones map[string][]string, replies map[string]zoneReply) Checker {
	t.Helper()
	addrHost := map[string]string{}
	next := 1
	return Checker{
		LookupNS: func(_ context.Context, name string) ([]*net.NS, error) {
			hosts, ok := zones[strings.TrimSuffix(name, ".")]
			if !ok {
				return nil, errors.New("no such host")
			}
			var out []*net.NS
			for _, host := range hosts {
				out = append(out, &net.NS{Host: host + "."})
			}
			return out, nil
		},
		LookupHost: func(_ context.Context, host string) ([]string, error) {
			addr := net.IPv4(192, 0, 2, byte(next)).String()
			next++
			addrHost[addr] = host
			return []string{addr}, nil
		},
		Exchange: func(_ context.Context, server string, query []byte) ([]byte, error) {
			addr, _, _ := net.SplitHostPort(server)
			reply, ok := replies[addrHost[addr]]
			if !ok {
				return nil, errors.New("timeout")
			}
			return buildReply(t, query, reply), nil
		},
	}
}

func buildReply(t *testing.T, query []byte, reply zoneReply) []byte {
	t.Helper()
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		t.Fatal(err)
	}
	if q.Header.RecursionDesired {
		t.Fatal("delegation queries must not ask for recursion")
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RCode: reply.rcode},
		Questions: q.Questions,
	}
	for _, ns := range reply.nameservers {
		msg.Authorities = append(msg.Authorities, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(reply.nsOwner + "."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 3600},
			Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName(ns + ".")},
		})
	}
	if reply.soaOwner != "" {
		msg.Authorities = append(msg.Authorities, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(reply.soaOwner + "."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 1200},
			Body: &dnsmessage.SOAResource{
				NS:   dnsmessage.MustNewName("ns1.nic." + reply.soaOwner + "."),
				MBox: dnsmessage.MustNewName("hostmaster.nic." + reply.soaOwner + "."),
			},
		})
	}
	body, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCheckDelegatedDomainIsRegistered(t *testing.T) {
	checker := fakeChecker(t,
		map[string][]string{"uy": {"a.nic.uy"}},
		map[string]zoneReply{"a.nic.uy": {nsOwner: "ka.uy", nameservers: []string{"sloan.ns.cloudflare.com", "jeff.ns.cloudflare.com"}}},
	)
	result, err := checker.Check(context.Background(), "KA.uy.")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusRegistered || result.Zone != "uy" {
		t.Fatalf("got %#v", result)
	}
	if strings.Join(result.Nameservers, ",") != "jeff.ns.cloudflare.com,sloan.ns.cloudflare.com" {
		t.Fatalf("nameservers: %v", result.Nameservers)
	}
	if !strings.Contains(result.Body, "ka.uy.\t3600\tIN\tNS\tjeff.ns.cloudflare.com.") {
		t.Fatalf("raw body:\n%s", result.Body)
	}
}

func TestCheckNXDOMAINIsUnregistered(t *testing.T) {
	checker := fakeChecker(t,
		map[string][]string{"al": {"nsx.nic.al"}},
		map[string]zoneReply{"nsx.nic.al": {rcode: dnsmessage.RCodeNameError, soaOwner: "al"}},
	)
	result, err := checker.Check(context.Background(), "free-name.al")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusUnregistered || len(result.Nameservers) != 0 {
		t.Fatalf("got %#v", result)
	}
	if !strings.Contains(result.Body, "NXDOMAIN") {
		t.Fatalf("raw body:\n%s", result.Body)
	}
}

func TestCheckFollowsReferralToSecondLevelZone(t *testing.T) {
	checker := fakeChecker(t,
		// com.uy has no NS of its own in the recursive view, so the check
		// starts at uy and is referred down.
		map[string][]string{"uy": {"a.nic.uy"}},
		map[string]zoneReply{
			"a.nic.uy":  {nsOwner: "com.uy", nameservers: []string{"ns.com.uy"}},
			"ns.com.uy": {nsOwner: "google.com.uy", nameservers: []string{"ns1.google.com"}},
		},
	)
	result, err := checker.Check(context.Background(), "google.com.uy")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusRegistered || result.Zone != "com.uy" {
		t.Fatalf("got %#v", result)
	}
}

func TestCheckNameWithoutDelegationIsUnknown(t *testing.T) {
	checker := fakeChecker(t,
		map[string][]string{"al": {"nsx.nic.al"}},
		map[string]zoneReply{"nsx.nic.al": {soaOwner: "al"}},
	)
	result, err := checker.Check(context.Background(), "gov.al")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusUnknown {
		t.Fatalf("got %#v", result)
	}
}

func TestCheckFallsBackToAnotherNameserver(t *testing.T) {
	checker := fakeChecker(t,
		map[string][]string{"uy": {"dead.nic.uy", "a.nic.uy"}},
		map[string]zoneReply{"a.nic.uy": {nsOwner: "ka.uy", nameservers: []string{"ns1.example.net"}}},
	)
	result, err := checker.Check(context.Background(), "ka.uy")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != model.StatusRegistered || !strings.HasPrefix(result.Server, "a.nic.uy") {
		t.Fatalf("got %#v", result)
	}
}

func TestCheckReportsUnreachableZone(t *testing.T) {
	checker := fakeChecker(t, map[string][]string{"uy": {"dead.nic.uy"}}, nil)
	if _, err := checker.Check(context.Background(), "ka.uy"); err == nil || !strings.Contains(err.Error(), "dead.nic.uy: timeout") {
		t.Fatalf("err = %v", err)
	}
}
