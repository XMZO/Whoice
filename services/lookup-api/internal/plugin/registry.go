package plugin

import (
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

const DefaultVersion = "v0.02pre"

type Registry struct {
	providers []providers.Provider
	parsers   []parsers.Parser
	plugins   []model.PluginInfo
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) RegisterProvider(provider providers.Provider, enabled ...bool) {
	isEnabled := true
	if len(enabled) > 0 {
		isEnabled = enabled[0]
	}
	r.providers = append(r.providers, provider)
	r.plugins = append(r.plugins, model.PluginInfo{
		Kind:    "provider",
		Name:    string(provider.Name()),
		Version: DefaultVersion,
		Enabled: isEnabled,
	})
}

func (r *Registry) RegisterParser(parser parsers.Parser) {
	r.parsers = append(r.parsers, parser)
	r.plugins = append(r.plugins, model.PluginInfo{
		Kind:    "parser",
		Name:    parser.Name(),
		Version: DefaultVersion,
		Enabled: true,
	})
}

func (r *Registry) RegisterBuiltIn(kind, name string, enabled bool) {
	r.plugins = append(r.plugins, model.PluginInfo{
		Kind:    kind,
		Name:    name,
		Version: DefaultVersion,
		Enabled: enabled,
	})
}

func (r *Registry) Providers() []providers.Provider {
	items := make([]providers.Provider, len(r.providers))
	copy(items, r.providers)
	return items
}

func (r *Registry) ParserRegistry() *parsers.Registry {
	items := make([]parsers.Parser, len(r.parsers))
	copy(items, r.parsers)
	return parsers.NewRegistry(items...)
}

func (r *Registry) Plugins() []model.PluginInfo {
	items := make([]model.PluginInfo, len(r.plugins))
	copy(items, r.plugins)
	return items
}
