package merger

import (
	"strings"
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
	result.Registrar.Source = pick(result.Registrar.Source, part.Registrar.Source)
	if result.Registrar.Confidence == nil {
		result.Registrar.Confidence = part.Registrar.Confidence
	}
	result.Registrar.Evidence = pick(result.Registrar.Evidence, part.Registrar.Evidence)
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
	seen := map[string]int{}
	for i, ns := range result.Nameservers {
		seen[ns.Host] = i
	}
	for _, ns := range part.Nameservers {
		if ns.Host == "" {
			continue
		}
		if index, ok := seen[ns.Host]; ok {
			result.Nameservers[index].Addresses = appendUniqueStrings(result.Nameservers[index].Addresses, ns.Addresses...)
			continue
		}
		result.Nameservers = append(result.Nameservers, ns)
		seen[ns.Host] = len(result.Nameservers) - 1
	}
}

func appendUniqueStrings(values []string, incoming ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range incoming {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		values = append(values, value)
		seen[value] = true
	}
	return values
}

func mergeDNSSEC(result *model.LookupResult, part *model.PartialResult) {
	if result.DNSSEC.Signed == nil && part.DNSSEC.Signed != nil {
		result.DNSSEC.Signed = part.DNSSEC.Signed
	}
	result.DNSSEC.Text = pick(result.DNSSEC.Text, part.DNSSEC.Text)
}

func mergeRegistrant(result *model.LookupResult, part *model.PartialResult) {
	result.Registrant.Name = mergeRegistrantField(result, "name", result.Registrant.Name, part.Registrant.Name, part)
	result.Registrant.Organization = mergeRegistrantField(result, "organization", result.Registrant.Organization, part.Registrant.Organization, part)
	result.Registrant.Country = mergeRegistrantField(result, "country", result.Registrant.Country, part.Registrant.Country, part)
	result.Registrant.Province = mergeRegistrantField(result, "province", result.Registrant.Province, part.Registrant.Province, part)
	result.Registrant.City = mergeRegistrantField(result, "city", result.Registrant.City, part.Registrant.City, part)
	result.Registrant.Address = mergeRegistrantField(result, "address", result.Registrant.Address, part.Registrant.Address, part)
	result.Registrant.PostalCode = mergeRegistrantField(result, "postalCode", result.Registrant.PostalCode, part.Registrant.PostalCode, part)
	result.Registrant.Email = mergeRegistrantField(result, "email", result.Registrant.Email, part.Registrant.Email, part)
	result.Registrant.Phone = mergeRegistrantField(result, "phone", result.Registrant.Phone, part.Registrant.Phone, part)
	result.Registrant.Extra = mergeRegistrationFields(result.Registrant.Extra, part.Registrant.Extra)
	result.Registrant.FieldSources = mergeRegistrantFieldSources(result.Registrant.FieldSources, part.Registrant.FieldSources)
	result.Registrant.Source = pick(result.Registrant.Source, part.Registrant.Source)
	if result.Registrant.Confidence == nil {
		result.Registrant.Confidence = part.Registrant.Confidence
	}
	result.Registrant.Evidence = pick(result.Registrant.Evidence, part.Registrant.Evidence)
}

func mergeRegistrantField(result *model.LookupResult, key, current, incoming string, part *model.PartialResult) string {
	incoming = strings.TrimSpace(incoming)
	if incoming == "" {
		return current
	}
	source := strings.TrimSpace(string(part.Source))
	if source == "" {
		source = strings.TrimSpace(part.Registrant.Source)
	}
	addRegistrantFieldSource(&result.Registrant, key, model.RegistrationField{
		Label:      key,
		Value:      incoming,
		Source:     source,
		Confidence: part.Registrant.Confidence,
		Evidence:   part.Registrant.Evidence,
	})
	return pick(current, incoming)
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

func mergeRegistrationFields(current, incoming []model.RegistrationField) []model.RegistrationField {
	if len(incoming) == 0 {
		return current
	}
	seen := map[string]bool{}
	for _, field := range current {
		seen[registrationFieldKey(field)] = true
	}
	out := current
	for _, field := range incoming {
		field.Label = strings.TrimSpace(field.Label)
		field.Value = strings.TrimSpace(field.Value)
		field.Source = strings.TrimSpace(field.Source)
		field.Evidence = strings.TrimSpace(field.Evidence)
		if field.Label == "" || field.Value == "" {
			continue
		}
		key := registrationFieldKey(field)
		if seen[key] {
			continue
		}
		out = append(out, field)
		seen[key] = true
	}
	return out
}

func mergeRegistrantFieldSources(current, incoming map[string][]model.RegistrationField) map[string][]model.RegistrationField {
	if len(incoming) == 0 {
		return current
	}
	out := current
	for key, values := range incoming {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		for _, value := range values {
			addRegistrantFieldSourceToMap(&out, key, value)
		}
	}
	return out
}

func addRegistrantFieldSource(registrant *model.RegistrantInfo, key string, field model.RegistrationField) {
	if registrant == nil {
		return
	}
	addRegistrantFieldSourceToMap(&registrant.FieldSources, key, field)
}

func addRegistrantFieldSourceToMap(target *map[string][]model.RegistrationField, key string, field model.RegistrationField) {
	key = strings.TrimSpace(key)
	field.Label = strings.TrimSpace(field.Label)
	field.Value = strings.TrimSpace(field.Value)
	field.Source = strings.TrimSpace(field.Source)
	field.Evidence = strings.TrimSpace(field.Evidence)
	if target == nil || key == "" || field.Value == "" {
		return
	}
	if *target == nil {
		*target = map[string][]model.RegistrationField{}
	}
	key = strings.TrimSpace(key)
	existing := (*target)[key]
	candidateKey := registrationFieldKey(field)
	for _, item := range existing {
		if registrationFieldKey(item) == candidateKey {
			return
		}
	}
	(*target)[key] = append(existing, field)
}

func registrationFieldKey(field model.RegistrationField) string {
	return strings.ToLower(strings.TrimSpace(field.Label)) + "\x00" +
		strings.ToLower(strings.TrimSpace(field.Value)) + "\x00" +
		strings.ToLower(strings.TrimSpace(field.Source))
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
