package dnsviz

import (
	"net/url"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func Apply(result *model.LookupResult) {
	if result == nil || result.Type != model.QueryDomain {
		return
	}
	domain := strings.ToLower(result.Domain.Name)
	if domain == "" {
		domain = strings.ToLower(result.NormalizedQuery)
	}
	if domain == "" {
		return
	}
	result.Enrichment.DNSViz = &model.DNSVizInfo{
		URL: "https://dnsviz.net/d/" + url.PathEscape(domain) + "/dnssec/",
	}
}
