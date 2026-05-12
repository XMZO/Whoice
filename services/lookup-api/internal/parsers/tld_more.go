package parsers

import (
	"context"
	"regexp"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type FRWHOISParser struct{}

func (FRWHOISParser) Name() string { return "whois-tld-fr" }

func (FRWHOISParser) Supports(raw model.RawResponse) bool {
	return raw.Source == model.SourceWHOIS && (strings.HasSuffix(strings.ToLower(raw.Query), ".fr") || strings.Contains(strings.ToLower(raw.Body), "eppstatus:"))
}

func (FRWHOISParser) Priority() int { return 88 }

func (FRWHOISParser) Parse(ctx context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	partial, err := WHOISParser{}.Parse(ctx, raw, q)
	if err != nil || partial.Status != model.StatusRegistered {
		return partial, err
	}
	fields := parseKeyValues(raw.Body)
	if url := firstValue(fields, "website"); url != "" {
		partial.Registrar.URL = url
	}
	partial.Dates.UpdatedAt = firstValue(fields, "last-update")
	statusSubject := raw.Body
	if beforeSource := beforeFirstSource(raw.Body); beforeSource != "" {
		statusSubject = beforeSource
	}
	statusFields := parseKeyValues(statusSubject)
	if values := valuesFor(statusFields, "eppstatus"); len(values) > 0 {
		partial.Statuses = nil
		for _, value := range values {
			code := strings.Fields(value)
			if len(code) == 0 {
				continue
			}
			partial.Statuses = append(partial.Statuses, model.DomainStatus{
				Code:   code[0],
				Label:  code[0],
				Source: string(raw.Source),
			})
		}
	}
	return partial, nil
}

type CNWHOISParser struct{}

func (CNWHOISParser) Name() string { return "whois-tld-cn" }

func (CNWHOISParser) Supports(raw model.RawResponse) bool {
	return raw.Source == model.SourceWHOIS && strings.HasSuffix(strings.ToLower(raw.Query), ".cn")
}

func (CNWHOISParser) Priority() int { return 88 }

func (CNWHOISParser) Parse(ctx context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	partial, err := WHOISParser{}.Parse(ctx, raw, q)
	if err != nil {
		return partial, err
	}
	fields := parseKeyValues(raw.Body)
	partial.Dates.CreatedAt = firstValue(fields, "registration time")
	partial.Dates.ExpiresAt = firstValue(fields, "expiration time")
	partial.Dates.CreatedAt = normalizeCNDate(partial.Dates.CreatedAt)
	partial.Dates.ExpiresAt = normalizeCNDate(partial.Dates.ExpiresAt)
	partial.Dates.UpdatedAt = normalizeCNDate(partial.Dates.UpdatedAt)
	return partial, nil
}

type BRWHOISParser struct{}

func (BRWHOISParser) Name() string { return "whois-tld-br" }

func (BRWHOISParser) Supports(raw model.RawResponse) bool {
	return raw.Source == model.SourceWHOIS && strings.HasSuffix(strings.ToLower(raw.Query), ".br")
}

func (BRWHOISParser) Priority() int { return 88 }

func (BRWHOISParser) Parse(ctx context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	partial, err := WHOISParser{}.Parse(ctx, raw, q)
	if err != nil {
		return partial, err
	}
	fields := parseKeyValues(raw.Body)
	partial.Dates.CreatedAt = firstDateToken(partial.Dates.CreatedAt)
	partial.Registrant.Country = firstValue(fields, "country")
	return partial, nil
}

var sourceBoundaryPattern = regexp.MustCompile(`(?im)^source\s*:`)

func beforeFirstSource(body string) string {
	index := sourceBoundaryPattern.FindStringIndex(body)
	if index == nil || index[0] <= 0 {
		return ""
	}
	return body[:index[0]]
}

func normalizeCNDate(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasSuffix(value, "Z") || strings.Contains(value, "T") {
		return value
	}
	if strings.Contains(value, " ") && len(value) >= 19 {
		return strings.Replace(value[:19], " ", "T", 1) + "+08:00"
	}
	return value
}

func firstDateToken(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value
	}
	return fields[0]
}
