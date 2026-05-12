package registrar

import (
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/data/registrars"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

func Apply(result *model.LookupResult, registry *registrars.Registry) {
	if result == nil || registry == nil || result.Type != model.QueryDomain {
		return
	}

	item, ok := match(result.Registrar, registry)
	if !ok {
		return
	}

	if result.Registrar.Name == "" {
		result.Registrar.Name = item.Name
	}
	if result.Registrar.IANAID == "" {
		result.Registrar.IANAID = item.IANAID
	}
	if result.Registrar.URL == "" {
		result.Registrar.URL = item.URL
	}
	if result.Registrar.Country == "" {
		result.Registrar.Country = item.Country
	}
}

func match(info model.RegistrarInfo, registry *registrars.Registry) (registrars.Registrar, bool) {
	if strings.TrimSpace(info.IANAID) != "" {
		if item, ok := registry.FindByIANAID(info.IANAID); ok {
			return item, true
		}
	}
	if strings.TrimSpace(info.Name) != "" {
		if item, ok := registry.FindByName(info.Name); ok {
			return item, true
		}
	}
	return registrars.Registrar{}, false
}
