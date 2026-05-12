package merger

import (
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Merger struct{}

func New() Merger {
	return Merger{}
}

func (Merger) Merge(q model.NormalizedQuery, parts []*model.PartialResult) *model.LookupResult {
	result := &model.LookupResult{
		Query:           q.Input,
		NormalizedQuery: q.Query,
		Type:            q.Type,
		Status:          model.StatusUnknown,
		Source:          model.SourceInfo{Used: []model.SourceName{}},
		Statuses:        []model.DomainStatus{},
		Nameservers:     []model.Nameserver{},
		Domain: model.DomainInfo{
			Name:             q.Query,
			UnicodeName:      q.UnicodeQuery,
			PunycodeName:     q.Query,
			Suffix:           q.Suffix,
			RegisteredDomain: q.RegisteredDomain,
		},
	}

	for _, part := range parts {
		if part == nil {
			continue
		}
		result.Source.Used = appendUniqueSource(result.Source.Used, part.Source)
		if result.Source.Primary == "" && part.Status == model.StatusRegistered {
			result.Source.Primary = part.Source
		}
		mergeStatus(result, part)
		mergeDomain(result, part)
		mergeRegistry(result, part)
		mergeRegistrar(result, part)
		mergeDates(result, part)
		mergeStatuses(result, part)
		mergeNameservers(result, part)
		mergeDNSSEC(result, part)
		mergeRegistrant(result, part)
		mergeNetwork(result, part)
		mergeRaw(result, part)
		result.Meta.Warnings = append(result.Meta.Warnings, part.Warnings...)
	}

	if result.Source.Primary == "" && len(result.Source.Used) > 0 {
		result.Source.Primary = result.Source.Used[0]
	}
	if result.Status == model.StatusUnknown && hasEvidence(result) {
		result.Status = model.StatusRegistered
	}
	if q.Type == model.QueryDomain && result.Status == model.StatusRegistered {
		result.Domain.Registered = true
	}
	calculateDateDiffs(result)
	return result
}

func mergeStatus(result *model.LookupResult, part *model.PartialResult) {
	switch part.Status {
	case model.StatusRegistered:
		if result.Status == model.StatusUnknown {
			result.Status = model.StatusRegistered
		}
	case model.StatusReserved:
		result.Status = model.StatusReserved
		result.Domain.Reserved = true
	case model.StatusUnregistered:
		if result.Status != model.StatusRegistered {
			result.Status = model.StatusUnregistered
		}
	}
}

func mergeDomain(result *model.LookupResult, part *model.PartialResult) {
	if part.Domain.Name != "" {
		result.Domain.Name = part.Domain.Name
	}
	if part.Domain.UnicodeName != "" {
		result.Domain.UnicodeName = part.Domain.UnicodeName
	}
	if part.Domain.PunycodeName != "" {
		result.Domain.PunycodeName = part.Domain.PunycodeName
	}
	if part.Domain.Suffix != "" {
		result.Domain.Suffix = part.Domain.Suffix
	}
	if part.Domain.RegisteredDomain != "" {
		result.Domain.RegisteredDomain = part.Domain.RegisteredDomain
	}
	if part.Domain.Reserved {
		result.Domain.Reserved = true
	}
}

func mergeRegistry(result *model.LookupResult, part *model.PartialResult) {
	result.Registry.Name = pick(result.Registry.Name, part.Registry.Name)
	result.Registry.Website = pick(result.Registry.Website, part.Registry.Website)
	result.Registry.WHOISServer = pick(result.Registry.WHOISServer, part.Registry.WHOISServer)
	result.Registry.RDAPServer = pick(result.Registry.RDAPServer, part.Registry.RDAPServer)
}

func mergeRegistrar(result *model.LookupResult, part *model.PartialResult) {
	result.Registrar.Name = pick(result.Registrar.Name, part.Registrar.Name)
	result.Registrar.URL = pick(result.Registrar.URL, part.Registrar.URL)
	result.Registrar.IANAID = pick(result.Registrar.IANAID, part.Registrar.IANAID)
	result.Registrar.Country = pick(result.Registrar.Country, part.Registrar.Country)
	result.Registrar.WHOISServer = pick(result.Registrar.WHOISServer, part.Registrar.WHOISServer)
	result.Registrar.RDAPServer = pick(result.Registrar.RDAPServer, part.Registrar.RDAPServer)
}

func mergeDates(result *model.LookupResult, part *model.PartialResult) {
	result.Dates.CreatedAt = pick(result.Dates.CreatedAt, part.Dates.CreatedAt)
	result.Dates.UpdatedAt = pick(result.Dates.UpdatedAt, part.Dates.UpdatedAt)
	result.Dates.ExpiresAt = pick(result.Dates.ExpiresAt, part.Dates.ExpiresAt)
	result.Dates.AvailableAt = pick(result.Dates.AvailableAt, part.Dates.AvailableAt)
}

func mergeStatuses(result *model.LookupResult, part *model.PartialResult) {
	seen := map[string]bool{}
	for _, status := range result.Statuses {
		seen[status.Code] = true
	}
	for _, status := range part.Statuses {
		if status.Code == "" || seen[status.Code] {
			continue
		}
		result.Statuses = append(result.Statuses, status)
		seen[status.Code] = true
	}
}

func mergeNameservers(result *model.LookupResult, part *model.PartialResult) {
	seen := map[string]bool{}
	for _, ns := range result.Nameservers {
		seen[ns.Host] = true
	}
	for _, ns := range part.Nameservers {
		if ns.Host == "" || seen[ns.Host] {
			continue
		}
		result.Nameservers = append(result.Nameservers, ns)
		seen[ns.Host] = true
	}
}

func mergeDNSSEC(result *model.LookupResult, part *model.PartialResult) {
	if result.DNSSEC.Signed == nil && part.DNSSEC.Signed != nil {
		result.DNSSEC.Signed = part.DNSSEC.Signed
	}
	result.DNSSEC.Text = pick(result.DNSSEC.Text, part.DNSSEC.Text)
}

func mergeRegistrant(result *model.LookupResult, part *model.PartialResult) {
	result.Registrant.Organization = pick(result.Registrant.Organization, part.Registrant.Organization)
	result.Registrant.Country = pick(result.Registrant.Country, part.Registrant.Country)
	result.Registrant.Province = pick(result.Registrant.Province, part.Registrant.Province)
	result.Registrant.Email = pick(result.Registrant.Email, part.Registrant.Email)
	result.Registrant.Phone = pick(result.Registrant.Phone, part.Registrant.Phone)
}

func mergeNetwork(result *model.LookupResult, part *model.PartialResult) {
	result.Network.CIDR = pick(result.Network.CIDR, part.Network.CIDR)
	result.Network.Range = pick(result.Network.Range, part.Network.Range)
	result.Network.Name = pick(result.Network.Name, part.Network.Name)
	result.Network.Type = pick(result.Network.Type, part.Network.Type)
	result.Network.OriginAS = pick(result.Network.OriginAS, part.Network.OriginAS)
	result.Network.Country = pick(result.Network.Country, part.Network.Country)
}

func mergeRaw(result *model.LookupResult, part *model.PartialResult) {
	result.Raw.WHOIS = pick(result.Raw.WHOIS, part.Raw.WHOIS)
	result.Raw.RDAP = pick(result.Raw.RDAP, part.Raw.RDAP)
	result.Raw.WHOISWeb = pick(result.Raw.WHOISWeb, part.Raw.WHOISWeb)
}

func pick(current, incoming string) string {
	if current != "" {
		return current
	}
	return incoming
}

func appendUniqueSource(values []model.SourceName, source model.SourceName) []model.SourceName {
	for _, value := range values {
		if value == source {
			return values
		}
	}
	return append(values, source)
}

func hasEvidence(result *model.LookupResult) bool {
	return result.Registrar.Name != "" ||
		result.Dates.CreatedAt != "" ||
		result.Dates.ExpiresAt != "" ||
		len(result.Statuses) > 0 ||
		len(result.Nameservers) > 0 ||
		result.Network.Range != "" ||
		result.Raw.RDAP != "" ||
		result.Raw.WHOIS != ""
}

func calculateDateDiffs(result *model.LookupResult) {
	now := time.Now().UTC()
	if created, ok := parseTime(result.Dates.CreatedAt); ok {
		days := int(now.Sub(created).Hours() / 24)
		result.Dates.AgeDays = &days
	}
	if expires, ok := parseTime(result.Dates.ExpiresAt); ok {
		days := int(expires.Sub(now).Hours() / 24)
		result.Dates.RemainingDays = &days
	}
}

func parseTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006.01.02 15:04:05",
		"02-Jan-2006",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
