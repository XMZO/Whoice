package parsers

import (
	"context"
	"regexp"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type WHOISParser struct{}

var unregisteredPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bno match\b`),
	regexp.MustCompile(`(?i)\bnot found\b`),
	regexp.MustCompile(`(?i)\bno data found\b`),
	regexp.MustCompile(`(?i)\bdomain not found\b`),
	regexp.MustCompile(`(?i)\bstatus:\s*free\b`),
	regexp.MustCompile(`(?i)\bstatus:\s*available\b`),
	regexp.MustCompile(`(?i)\bno entries found\b`),
	regexp.MustCompile(`(?i)\bno information\b`),
	regexp.MustCompile(`(?i)\bno record found\b`),
	regexp.MustCompile(`(?i)\bno such domain\b`),
	regexp.MustCompile(`(?i)\bnot registered\b`),
	regexp.MustCompile(`(?i)\bhas not been registered\b`),
	regexp.MustCompile(`(?i)\bdomain (?:name )?is available\b`),
	regexp.MustCompile(`(?i)\bdomain unknown\b`),
	regexp.MustCompile(`(?i)\bobject_not_found\b`),
	regexp.MustCompile(`(?i)\bis available for registration\b`),
}

var reservedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\breserved by (?:the )?registry\b`),
	regexp.MustCompile(`(?i)\breserved domain\b`),
	regexp.MustCompile(`(?i)\breserved domain name\b`),
	regexp.MustCompile(`(?i)\bdomain name is reserved\b`),
	regexp.MustCompile(`(?i)\bdomain (?:name )?(?:is )?reserved\b`),
	regexp.MustCompile(`(?i)\bhas been reserved\b`),
	regexp.MustCompile(`(?i)\breserved word\b`),
	regexp.MustCompile(`(?i)\bstatus:\s*not allowed\b`),
	regexp.MustCompile(`(?i)\bstatus:\s*forbidden\b`),
	regexp.MustCompile(`(?i)\bstatus:\s*prohibited\b`),
	regexp.MustCompile(`(?i)\bdomain(?: name)? is not allowed\b`),
	regexp.MustCompile(`(?i)\bname is restricted\b`),
	regexp.MustCompile(`(?i)\bcannot be registered\b`),
	regexp.MustCompile(`(?i)\bcan ?not be registered\b`),
}

func (WHOISParser) Name() string { return "whois-generic" }

func (WHOISParser) Supports(raw model.RawResponse) bool {
	return raw.Source == model.SourceWHOIS || raw.Source == model.SourceWHOISWeb
}

func (WHOISParser) Priority() int { return 50 }

func (WHOISParser) Parse(_ context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	partial := &model.PartialResult{
		Source: raw.Source,
		Status: model.StatusRegistered,
		Raw:    rawDataForWHOISSource(raw),
		Domain: model.DomainInfo{
			Name:             q.Query,
			PunycodeName:     q.Query,
			UnicodeName:      q.UnicodeQuery,
			Suffix:           q.Suffix,
			RegisteredDomain: q.RegisteredDomain,
		},
	}

	if raw.Body == "" {
		partial.Status = model.StatusUnknown
		partial.Warnings = append(partial.Warnings, "empty WHOIS response")
		return partial, nil
	}
	if raw.Source == model.SourceWHOISWeb && isWHOISWebNotice(raw.Body) {
		partial.Status = model.StatusUnknown
		partial.Warnings = append(partial.Warnings, "WHOIS Web fallback requires manual lookup")
		return partial, nil
	}
	if matchesAny(reservedPatterns, raw.Body) {
		partial.Status = model.StatusReserved
		partial.Domain.Reserved = true
	}
	if matchesAny(unregisteredPatterns, raw.Body) {
		partial.Status = model.StatusUnregistered
	}

	fields := parseKeyValues(raw.Body)

	partial.Domain.Name = firstValue(fields, "domain name", "domain")
	if partial.Domain.Name == "" && q.Type == model.QueryDomain {
		partial.Domain.Name = q.Query
	}
	partial.Domain.PunycodeName = partial.Domain.Name
	partial.Domain.UnicodeName = q.UnicodeQuery
	partial.Domain.Suffix = q.Suffix
	partial.Domain.RegisteredDomain = q.RegisteredDomain
	partial.Domain.Registered = partial.Status == model.StatusRegistered && q.Type == model.QueryDomain

	partial.Registry.WHOISServer = firstValue(fields, "whois", "whois server", "registry whois server")
	partial.Registrar.Name = firstValue(fields, "registrar", "sponsoring registrar")
	partial.Registrar.URL = normalizeRegistrarURL(firstValue(fields, "registrar url", "sponsoring registrar url", "registrar website", "registrar-url", "registration service url"))
	if registrarName, registrarURL := splitRegistrarURL(partial.Registrar.Name); registrarURL != "" && partial.Registrar.URL == "" {
		partial.Registrar.Name = registrarName
		partial.Registrar.URL = registrarURL
	}
	partial.Registrar.IANAID = firstValue(fields, "registrar iana id", "iana id")
	partial.Registrar.WHOISServer = firstValue(fields, "registrar whois server")
	partial.Dates.CreatedAt = firstValue(fields, "creation date", "created", "created on", "registered on")
	partial.Dates.ExpiresAt = firstValue(fields, "registry expiry date", "expiration date", "expiry date", "expires", "paid-till")
	partial.Dates.UpdatedAt = firstValue(fields, "updated date", "last updated", "modified", "changed")
	partial.DNSSEC.Text = firstValue(fields, "dnssec")

	for _, status := range valuesFor(fields, "domain status", "status") {
		code := strings.Fields(status)
		if len(code) == 0 {
			continue
		}
		partial.Statuses = append(partial.Statuses, model.DomainStatus{
			Code:   code[0],
			Label:  code[0],
			Source: string(model.SourceWHOIS),
		})
	}

	for _, ns := range valuesFor(fields, "name server", "nserver", "nameserver") {
		nsFields := strings.Fields(ns)
		if len(nsFields) == 0 {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(nsFields[0], "."))
		if host != "" && !hasNameserver(partial.Nameservers, host) {
			partial.Nameservers = append(partial.Nameservers, model.Nameserver{Host: host})
		}
	}

	partial.Registrant.Name = firstValue(fields, "registrant name", "registrant", "owner name")
	partial.Registrant.Organization = firstValue(fields, "registrant organization", "registrant org", "org", "organization", "owner organization")
	partial.Registrant.Country = firstValue(fields, "registrant country", "owner country")
	partial.Registrant.Province = firstValue(fields, "registrant state/province", "registrant province", "registrant state", "owner state", "owner province")
	partial.Registrant.City = firstValue(fields, "registrant city", "owner city")
	partial.Registrant.Address = firstValue(fields, "registrant street", "registrant address", "owner address")
	partial.Registrant.PostalCode = firstValue(fields, "registrant postal code", "registrant zip", "owner postal code")
	partial.Registrant.Email = firstValue(fields, "registrant email", "registrant contact email", "owner email", "email")
	partial.Registrant.Phone = firstValue(fields, "registrant phone", "registrant phone number", "owner phone", "phone")

	partial.Network.CIDR = firstValue(fields, "cidr")
	partial.Network.Range = firstValue(fields, "netrange", "inetnum", "inet6num")
	partial.Network.Name = firstValue(fields, "netname", "network name")
	partial.Network.Type = firstValue(fields, "nettype")
	partial.Network.OriginAS = firstValue(fields, "originas", "origin as")
	partial.Network.Country = firstValue(fields, "country")

	return partial, nil
}

func parseKeyValues(body string) map[string][]string {
	fields := map[string][]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		fields[key] = append(fields[key], value)
	}
	return fields
}

func firstValue(fields map[string][]string, keys ...string) string {
	for _, key := range keys {
		values := fields[strings.ToLower(key)]
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func valuesFor(fields map[string][]string, keys ...string) []string {
	var values []string
	for _, key := range keys {
		values = append(values, fields[strings.ToLower(key)]...)
	}
	return values
}

func matchesAny(patterns []*regexp.Regexp, body string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

func hasNameserver(values []model.Nameserver, host string) bool {
	for _, value := range values {
		if value.Host == host {
			return true
		}
	}
	return false
}

func rawDataForWHOISSource(raw model.RawResponse) model.RawData {
	if raw.Source == model.SourceWHOISWeb {
		return model.RawData{WHOISWeb: raw.Body}
	}
	return model.RawData{WHOIS: raw.Body}
}

func isWHOISWebNotice(body string) bool {
	body = strings.TrimSpace(strings.ToLower(body))
	return strings.HasPrefix(body, "whois web fallback notice:") ||
		strings.HasPrefix(body, "please visit ")
}

var registrarURLPattern = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]{2,}(?::\d+)?(?:/.*)?$`)

func normalizeRegistrarURL(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, " \t\r\n<>[]()'\"")
	if value == "" {
		return ""
	}
	if extracted := firstURL(value); extracted != "" {
		return extracted
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	if registrarURLPattern.MatchString(value) {
		return "http://" + value
	}
	return ""
}

func splitRegistrarURL(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	left, rest, ok := strings.Cut(value, "(")
	if !ok {
		return value, ""
	}
	candidate, _, ok := strings.Cut(rest, ")")
	if !ok {
		return value, ""
	}
	url := normalizeRegistrarURL(candidate)
	if url == "" {
		return value, ""
	}
	name := strings.TrimSpace(left)
	if name == "" {
		name = value
	}
	return name, url
}
