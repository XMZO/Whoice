package normalize

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/publicsuffixes"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

var asnPattern = regexp.MustCompile(`(?i)^AS([0-9]{1,10})$`)

type Normalizer struct {
	suffixRules publicsuffixes.Rules
}

type InputError struct {
	Message string
}

func (e InputError) Error() string {
	return e.Message
}

func New(dataDir ...string) Normalizer {
	dir := ""
	if len(dataDir) > 0 {
		dir = dataDir[0]
	}
	return Normalizer{suffixRules: publicsuffixes.NewDefaultRules(dir)}
}

func (n Normalizer) Normalize(input string) (*model.NormalizedQuery, error) {
	original := input
	input = CleanUserInput(input)
	if input == "" {
		return nil, InputError{Message: "query is required"}
	}
	if len(input) > 512 {
		return nil, InputError{Message: "query is too long"}
	}

	if prefix, err := netip.ParsePrefix(input); err == nil {
		return &model.NormalizedQuery{
			Input: original,
			Query: prefix.String(),
			Type:  model.QueryCIDR,
		}, nil
	}

	if addr, err := netip.ParseAddr(trimIPv6Brackets(input)); err == nil {
		queryType := model.QueryIPv4
		if addr.Is6() {
			queryType = model.QueryIPv6
		}
		return &model.NormalizedQuery{
			Input: original,
			Query: addr.String(),
			Type:  queryType,
		}, nil
	}

	if matches := asnPattern.FindStringSubmatch(input); matches != nil {
		asn64, err := strconv.ParseUint(matches[1], 10, 32)
		if err != nil {
			return nil, InputError{Message: "invalid ASN"}
		}
		return &model.NormalizedQuery{
			Input: original,
			Query: "AS" + strconv.FormatUint(asn64, 10),
			Type:  model.QueryASN,
			ASN:   uint32(asn64),
		}, nil
	}

	host := extractHost(input)
	host = normalizeDomainSeparators(host)
	host = strings.Trim(strings.ToLower(host), ".")
	host = strings.TrimSuffix(host, ":")
	if host == "" {
		return nil, InputError{Message: "query is not a valid domain, IP, ASN, or CIDR"}
	}

	if ip := net.ParseIP(host); ip != nil {
		return n.Normalize(host)
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return nil, InputError{Message: "query is not a valid domain: " + err.Error()}
	}
	unicodeHost, _ := idna.Lookup.ToUnicode(ascii)

	if !looksLikeDomain(ascii) {
		return nil, InputError{Message: "query is not a valid domain"}
	}

	registeredDomain, _ := publicsuffix.EffectiveTLDPlusOne(ascii)
	suffix, _ := publicsuffix.PublicSuffix(ascii)
	if overlaySuffix, ok := n.suffixRules.PublicSuffix(ascii); ok && (n.suffixRules.IsAuthoritative() || publicsuffixes.MoreSpecific(overlaySuffix, suffix)) {
		suffix = overlaySuffix
		registeredDomain = publicsuffixes.EffectiveTLDPlusOne(ascii, suffix)
	}

	return &model.NormalizedQuery{
		Input:            original,
		Query:            ascii,
		UnicodeQuery:     unicodeHost,
		Type:             model.QueryDomain,
		Host:             ascii,
		Suffix:           suffix,
		RegisteredDomain: registeredDomain,
	}, nil
}

func cleanInput(input string) string {
	input = strings.TrimSpace(input)
	var builder strings.Builder
	for _, r := range input {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			continue
		}
		builder.WriteRune(r)
	}
	return strings.TrimSpace(builder.String())
}

func CleanUserInput(input string) string {
	return normalizeDomainSeparators(cleanInput(input))
}

func normalizeDomainSeparators(input string) string {
	var builder strings.Builder
	for _, r := range input {
		switch r {
		case ',', '，', '。', '｡', '．':
			builder.WriteRune('.')
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func trimIPv6Brackets(input string) string {
	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		return strings.TrimPrefix(strings.TrimSuffix(input, "]"), "[")
	}
	return input
}

func extractHost(input string) string {
	if strings.Contains(input, "://") {
		if parsed, err := url.Parse(input); err == nil && parsed.Host != "" {
			return stripPort(parsed.Host)
		}
	}

	if strings.Contains(input, "/") && !strings.Contains(input, "://") {
		if parsed, err := url.Parse("https://" + input); err == nil && parsed.Host != "" {
			return stripPort(parsed.Host)
		}
	}

	return stripPort(input)
}

func stripPort(host string) string {
	host = strings.Trim(host, "[]")
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.Count(host, ":") == 1 {
		if h, p, ok := strings.Cut(host, ":"); ok && isDigits(p) {
			return h
		}
	}
	return host
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeDomain(host string) bool {
	if len(host) < 1 || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 1 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
