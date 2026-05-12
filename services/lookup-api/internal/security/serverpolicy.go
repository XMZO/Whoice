package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ServerPolicy struct {
	AllowPrivate bool
	Resolver     *net.Resolver
}

func NewServerPolicy(allowPrivate bool) ServerPolicy {
	return ServerPolicy{
		AllowPrivate: allowPrivate,
		Resolver:     net.DefaultResolver,
	}
}

func (p ServerPolicy) AllowRDAP(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("invalid RDAP server URL")
	}
	if parsed.User != nil {
		return errors.New("RDAP server URL must not include user info")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("RDAP server URL must use http or https")
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("RDAP server URL is missing host")
	}
	return p.allowHost(ctx, host)
}

func (p ServerPolicy) AllowWHOIS(ctx context.Context, server string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return errors.New("WHOIS server is empty")
	}
	if strings.Contains(server, "://") || strings.ContainsAny(server, "/\\?#") {
		return errors.New("WHOIS server must be a host or host:port")
	}
	if strings.ContainsAny(server, " \t\r\n") {
		return errors.New("WHOIS server must not contain whitespace")
	}

	host := server
	if strings.Contains(server, ":") {
		if parsedHost, port, err := net.SplitHostPort(server); err == nil {
			host = parsedHost
			if err := validatePort(port); err != nil {
				return err
			}
		} else if strings.Count(server, ":") == 1 {
			parsedHost, port, ok := strings.Cut(server, ":")
			if !ok || parsedHost == "" {
				return errors.New("invalid WHOIS server")
			}
			host = parsedHost
			if err := validatePort(port); err != nil {
				return err
			}
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return errors.New("WHOIS server is missing host")
	}
	return p.allowHost(ctx, host)
}

func (p ServerPolicy) allowHost(ctx context.Context, host string) error {
	if p.AllowPrivate {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return errors.New("private or local server targets are not allowed")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if blockedAddr(addr) {
			return errors.New("private or local server targets are not allowed")
		}
		return nil
	}

	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := resolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve server host: %w", err)
	}
	if len(addrs) == 0 {
		return errors.New("server host resolved to no addresses")
	}
	for _, addr := range addrs {
		if blockedAddr(addr) {
			return errors.New("private or local server targets are not allowed")
		}
	}
	return nil
}

func validatePort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return errors.New("invalid WHOIS server port")
	}
	return nil
}

func blockedAddr(addr netip.Addr) bool {
	return !addr.IsValid() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified()
}
