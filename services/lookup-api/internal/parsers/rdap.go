package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type RDAPParser struct{}

func (RDAPParser) Name() string { return "rdap" }

func (RDAPParser) Supports(raw model.RawResponse) bool {
	return raw.Source == model.SourceRDAP
}

func (RDAPParser) Priority() int { return 100 }

func (RDAPParser) Parse(_ context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	partial := &model.PartialResult{
		Source: raw.Source,
		Status: model.StatusUnknown,
		Raw:    model.RawData{RDAP: raw.Body},
	}

	if raw.StatusCode == 404 {
		partial.Status = model.StatusUnregistered
		return partial, nil
	}
	if raw.StatusCode >= 400 {
		partial.Warnings = append(partial.Warnings, fmt.Sprintf("RDAP returned HTTP %d", raw.StatusCode))
		return partial, nil
	}
	if raw.Body == "" {
		partial.Warnings = append(partial.Warnings, "empty RDAP response")
		return partial, nil
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(raw.Body), &doc); err != nil {
		partial.Warnings = append(partial.Warnings, "invalid RDAP JSON")
		return partial, nil
	}

	partial.Status = model.StatusRegistered
	partial.Registry.RDAPServer = raw.Server
	partial.Registry.WHOISServer = stringField(doc, "port43")

	if name := firstNonEmpty(stringField(doc, "ldhName"), stringField(doc, "unicodeName"), q.Query); name != "" {
		partial.Domain.Name = strings.ToLower(strings.TrimSuffix(name, "."))
		partial.Domain.PunycodeName = partial.Domain.Name
		partial.Domain.UnicodeName = firstNonEmpty(stringField(doc, "unicodeName"), q.UnicodeQuery)
		partial.Domain.Suffix = q.Suffix
		partial.Domain.RegisteredDomain = q.RegisteredDomain
		partial.Domain.Registered = q.Type == model.QueryDomain
	}

	partial.Statuses = parseStatuses(doc)
	partial.Nameservers = parseNameservers(doc)
	partial.Dates = parseEvents(doc)
	partial.Registrar, partial.Registrant = parseEntities(doc)
	partial.DNSSEC = parseDNSSEC(doc)
	partial.Network = parseNetwork(doc, q)

	return partial, nil
}

func parseStatuses(doc map[string]any) []model.DomainStatus {
	values, ok := doc["status"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var statuses []model.DomainStatus
	for _, value := range values {
		code := strings.TrimSpace(fmt.Sprint(value))
		if code == "" || seen[strings.ToLower(code)] {
			continue
		}
		seen[strings.ToLower(code)] = true
		statuses = append(statuses, model.DomainStatus{
			Code:   code,
			Label:  code,
			URL:    "https://icann.org/epp",
			Source: string(model.SourceRDAP),
		})
	}
	return statuses
}

func parseNameservers(doc map[string]any) []model.Nameserver {
	values, ok := doc["nameservers"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var nameservers []model.Nameserver
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		host := firstNonEmpty(stringField(item, "ldhName"), stringField(item, "unicodeName"))
		hostFields := strings.Fields(host)
		if len(hostFields) == 0 {
			continue
		}
		host = strings.ToLower(strings.TrimSuffix(hostFields[0], "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		nameservers = append(nameservers, model.Nameserver{Host: host})
	}
	return nameservers
}

func parseEvents(doc map[string]any) model.DateInfo {
	values, ok := doc["events"].([]any)
	if !ok {
		return model.DateInfo{}
	}
	var dates model.DateInfo
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		action := strings.ToLower(stringField(item, "eventAction"))
		date := stringField(item, "eventDate")
		if date == "" {
			continue
		}
		switch action {
		case "registration":
			dates.CreatedAt = firstNonEmpty(dates.CreatedAt, date)
		case "expiration", "registrar expiration", "soft expiration":
			dates.ExpiresAt = firstNonEmpty(dates.ExpiresAt, date)
		case "last changed", "last update of rdap database", "last update":
			dates.UpdatedAt = firstNonEmpty(dates.UpdatedAt, date)
		}
	}
	return dates
}

func parseEntities(doc map[string]any) (model.RegistrarInfo, model.RegistrantInfo) {
	values, ok := doc["entities"].([]any)
	if !ok {
		return model.RegistrarInfo{}, model.RegistrantInfo{}
	}

	var registrar model.RegistrarInfo
	var registrant model.RegistrantInfo

	for _, value := range values {
		entity, ok := value.(map[string]any)
		if !ok {
			continue
		}
		roles := stringSlice(entity["roles"])
		if contains(roles, "registrar") {
			vcard := vcardMap(entity)
			registrar.Name = firstNonEmpty(registrar.Name, vcard["fn"], vcard["org"], stringField(entity, "handle"))
			registrar.URL = firstNonEmpty(registrar.URL, registrarEntityURL(entity, vcard["url"]))
			for _, publicID := range anySlice(entity["publicIds"]) {
				item, ok := publicID.(map[string]any)
				if !ok {
					continue
				}
				if strings.EqualFold(stringField(item, "type"), "IANA Registrar ID") {
					registrar.IANAID = firstNonEmpty(registrar.IANAID, stringField(item, "identifier"))
				}
			}
		}
		if contains(roles, "registrant") {
			vcard := vcardMap(entity)
			if distinctRDAPName := distinctRegistrantName(vcard["fn"], vcard["org"]); distinctRDAPName != "" {
				registrant.Name = firstNonEmpty(registrant.Name, distinctRDAPName)
			}
			registrant.Organization = firstNonEmpty(registrant.Organization, vcard["org"], vcard["fn"])
			registrant.Country = firstNonEmpty(registrant.Country, vcard["country-name"])
			registrant.Province = firstNonEmpty(registrant.Province, vcard["region"])
			registrant.City = firstNonEmpty(registrant.City, vcard["locality"])
			registrant.Address = firstNonEmpty(registrant.Address, vcard["street-address"])
			registrant.PostalCode = firstNonEmpty(registrant.PostalCode, vcard["postal-code"])
			registrant.Email = firstNonEmpty(registrant.Email, vcard["email"])
			registrant.Phone = firstNonEmpty(registrant.Phone, strings.TrimPrefix(vcard["tel"], "tel:"))
		}
	}

	return registrar, registrant
}

func distinctRegistrantName(name, organization string) string {
	name = strings.TrimSpace(name)
	organization = strings.TrimSpace(organization)
	if name == "" || organization == "" || strings.EqualFold(name, organization) {
		return ""
	}
	return name
}

func registrarEntityURL(entity map[string]any, vcardURL string) string {
	if url := normalizeRegistrarURL(vcardURL); url != "" {
		return url
	}
	if url := registrarEntityLinkURL(entity); url != "" {
		return url
	}
	return normalizeRegistrarURL(stringField(entity, "url"))
}

func registrarEntityLinkURL(entity map[string]any) string {
	links := anySlice(entity["links"])
	for _, value := range links {
		link, ok := value.(map[string]any)
		if !ok {
			continue
		}
		title := strings.ToLower(stringField(link, "title"))
		if strings.Contains(title, "registrar") && strings.Contains(title, "website") {
			if url := normalizeRegistrarURL(stringField(link, "href")); url != "" {
				return url
			}
		}
	}
	for _, value := range links {
		link, ok := value.(map[string]any)
		if !ok || rdapLinkLooksLikeAPI(link) {
			continue
		}
		if url := normalizeRegistrarURL(stringField(link, "href")); url != "" {
			return url
		}
	}
	return ""
}

func rdapLinkLooksLikeAPI(link map[string]any) bool {
	rel := strings.ToLower(stringField(link, "rel"))
	mediaType := strings.ToLower(stringField(link, "type"))
	href := strings.ToLower(stringField(link, "href"))
	if mediaType == "application/rdap+json" || rel == "self" {
		return true
	}
	return strings.Contains(href, "/rdap/") || strings.Contains(href, "rdap.")
}

func parseDNSSEC(doc map[string]any) model.DNSSECInfo {
	secure, ok := doc["secureDNS"].(map[string]any)
	if !ok {
		return model.DNSSECInfo{}
	}
	if signed, ok := secure["delegationSigned"].(bool); ok {
		text := "unsigned"
		if signed {
			text = "signed"
		}
		return model.DNSSECInfo{Signed: &signed, Text: text}
	}
	return model.DNSSECInfo{}
}

func parseNetwork(doc map[string]any, q model.NormalizedQuery) model.NetworkInfo {
	network := model.NetworkInfo{
		Name:     stringField(doc, "name"),
		Type:     stringField(doc, "type"),
		Country:  stringField(doc, "country"),
		OriginAS: "",
	}
	start := stringField(doc, "startAddress")
	end := stringField(doc, "endAddress")
	if start != "" && end != "" {
		network.Range = start + " - " + end
		network.CIDR = rangeCIDR(start, end, q)
	}
	if startAS := stringField(doc, "startAutnum"); startAS != "" {
		endAS := stringField(doc, "endAutnum")
		if endAS != "" && endAS != startAS {
			network.Range = "AS" + startAS + " - AS" + endAS
		}
		network.OriginAS = "AS" + startAS
	} else if q.Type == model.QueryASN {
		network.OriginAS = q.Query
	}
	return network
}

func rangeCIDR(start, end string, q model.NormalizedQuery) string {
	if q.Type == model.QueryCIDR && q.Query != "" {
		return q.Query
	}
	startAddr, startErr := netip.ParseAddr(start)
	endAddr, endErr := netip.ParseAddr(end)
	if startErr != nil || endErr != nil || startAddr.BitLen() != endAddr.BitLen() {
		return start + "-" + end
	}
	if startAddr == endAddr {
		return startAddr.String() + "/" + fmt.Sprint(startAddr.BitLen())
	}
	return start + "-" + end
}

func vcardMap(entity map[string]any) map[string]string {
	result := map[string]string{}
	vcardArray, ok := entity["vcardArray"].([]any)
	if !ok || len(vcardArray) < 2 {
		return result
	}
	fields, ok := vcardArray[1].([]any)
	if !ok {
		return result
	}
	for _, rawField := range fields {
		field, ok := rawField.([]any)
		if !ok || len(field) < 4 {
			continue
		}
		key := strings.ToLower(fmt.Sprint(field[0]))
		value := fmt.Sprint(field[3])
		if value != "" && value != "<nil>" {
			result[key] = value
		}
	}
	return result
}

func stringField(doc map[string]any, key string) string {
	value, ok := doc[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func stringSlice(value any) []string {
	if text, ok := value.(string); ok {
		text = strings.TrimSpace(text)
		if text != "" {
			return []string{text}
		}
		return nil
	}
	var result []string
	for _, item := range anySlice(value) {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			result = append(result, text)
		}
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
