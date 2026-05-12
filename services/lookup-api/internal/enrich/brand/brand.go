package brand

import (
	"net/url"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/brandmap"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func Apply(result *model.LookupResult, registry *brandmap.Registry) {
	if result == nil {
		return
	}
	if registry == nil {
		registry, _ = brandmap.NewSnapshotRegistry()
	}
	if result.Registrar.Brand == nil {
		if brand := matchBrand(registry.RegistrarRules(), result.Registrar.Name, result.Registrar.URL); brand != nil {
			result.Registrar.Brand = brand
		}
	}
	for i := range result.Nameservers {
		if result.Nameservers[i].Brand != nil {
			continue
		}
		if brand := matchBrand(registry.NameserverRules(), result.Nameservers[i].Host); brand != nil {
			result.Nameservers[i].Brand = brand
		}
	}
}

func matchBrand(rules []brandmap.Rule, values ...string) *model.Brand {
	haystack := normalizedHaystack(values...)
	if haystack == "" {
		return nil
	}
	for _, item := range rules {
		for _, pattern := range item.Patterns {
			if patternMatches(haystack, pattern) {
				return &model.Brand{Name: item.Name, Slug: item.Slug, Color: item.Color}
			}
		}
	}
	return nil
}

func patternMatches(haystack, pattern string) bool {
	needle := normalize(pattern)
	if needle == "" {
		return false
	}
	return strings.Contains(haystack, needle)
}

func normalizedHaystack(values ...string) string {
	var parts []string
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		parts = append(parts, value)
		if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
			parts = append(parts, parsed.Host)
		}
	}
	return normalize(strings.Join(parts, " "))
}

func normalize(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "", "-", "", "_", "", ",", "", ".", "")
	return replacer.Replace(value)
}
