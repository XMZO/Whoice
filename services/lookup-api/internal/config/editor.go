package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Helpers for the Web admin panel: read the file-only configuration, report which
// fields environment variables override, and write the file back atomically.

func tomlString(value string) string {
	return `"` + escapeTOMLString(value) + `"`
}

func tomlBool(value bool) string {
	return strconv.FormatBool(value)
}

func tomlInt(value int) string {
	return strconv.Itoa(value)
}

func tomlFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func tomlList(values []string) string {
	return "[" + tomlStringList(values) + "]"
}

func tomlMultilineList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for _, value := range values {
		b.WriteString("  " + tomlString(value) + ",\n")
	}
	b.WriteString("]")
	return b.String()
}

// tomlMultilineString prefers a literal ''' block so prompts stay readable, and
// falls back to an escaped basic string when the text itself contains '''.
func tomlMultilineString(value string) string {
	if !strings.Contains(value, "'''") && !strings.HasSuffix(value, "'") {
		return "'''" + value + "'''"
	}
	return tomlString(value)
}

func FormatDuration(value time.Duration) string {
	switch {
	case value <= 0:
		return "0s"
	case value%time.Hour == 0:
		return strconv.FormatInt(int64(value/time.Hour), 10) + "h"
	case value%time.Minute == 0:
		return strconv.FormatInt(int64(value/time.Minute), 10) + "m"
	case value%time.Second == 0:
		return strconv.FormatInt(int64(value/time.Second), 10) + "s"
	case value%time.Millisecond == 0:
		return strconv.FormatInt(int64(value/time.Millisecond), 10) + "ms"
	default:
		return value.String()
	}
}

func FormatCacheDuration(value time.Duration) string {
	switch {
	case value < 0:
		return "forever"
	case value == 0:
		return "0"
	default:
		return FormatDuration(value)
	}
}

func tomlDuration(value time.Duration) string {
	return tomlString(FormatDuration(value))
}

func tomlCacheDuration(value time.Duration) string {
	return tomlString(FormatCacheDuration(value))
}

func icpSignLine(cfg Config) string {
	if cfg.ICPSign == "" || cfg.ICPSign == Default().ICPSign {
		return ""
	}
	return "sign = " + tomlString(cfg.ICPSign) + "\n"
}

// LoadFileOnly reads defaults plus the config file, without environment overrides
// or validation. It is the base the admin panel edits and writes back.
func LoadFileOnly(path string) (Config, error) {
	cfg := Default()
	path = strings.TrimSpace(path)
	if path == "" {
		return cfg, errors.New("no config file path is active")
	}
	cfg.ConfigPath = path
	if err := applyFile(&cfg, path); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// WithEnv returns cfg with environment overrides applied, as the runtime sees it.
func WithEnv(cfg Config) Config {
	applyEnv(&cfg)
	return cfg
}

// envBindings maps environment variables to the settings path they override.
var envBindings = map[string]string{
	"WHOICE_API_ADDR": "server.addr", "WHOICE_DATA_DIR": "server.data_dir",
	"WHOICE_TRUST_PROXY": "server.trust_proxy", "WHOICE_ALLOW_CUSTOM_SERVERS": "server.allow_custom_servers",
	"WHOICE_ALLOW_PRIVATE_SERVERS": "server.allow_private_servers",
	"WHOICE_API_ENABLED": "api.enabled", "WHOICE_API_IP_ALLOWLIST": "api.ip_allowlist",
	"WHOICE_API_HEALTH_ENABLED": "api.endpoints.health", "WHOICE_API_VERSION_ENABLED": "api.endpoints.version",
	"WHOICE_API_CAPABILITIES_ENABLED": "api.endpoints.capabilities", "WHOICE_API_METRICS_ENABLED": "api.endpoints.metrics",
	"WHOICE_API_LOOKUP_ENABLED": "api.endpoints.lookup", "WHOICE_API_LOOKUP_AI_ENABLED": "api.endpoints.lookup_ai",
	"WHOICE_API_LOOKUP_ENRICH_ENABLED": "api.endpoints.lookup_enrich", "WHOICE_API_ICP_ENABLED": "api.endpoints.icp",
	"WHOICE_API_ADMIN_ENABLED": "api.endpoints.admin", "WHOICE_API_ADMIN_STATUS_ENABLED": "api.endpoints.admin_status",
	"WHOICE_API_ADMIN_CONFIG_ENABLED": "api.endpoints.admin_config",
	"WHOICE_AUTH_MODE": "auth.mode", "WHOICE_SITE_PASSWORD": "auth.site_password", "WHOICE_API_TOKENS": "auth.api_tokens",
	"WHOICE_LOOKUP_TIMEOUT": "lookup.timeout", "WHOICE_PROVIDER_TIMEOUT": "lookup.provider_timeout",
	"WHOICE_RDAP_ENABLED": "lookup.rdap_enabled", "WHOICE_WHOIS_ENABLED": "lookup.whois_enabled",
	"WHOICE_WHOIS_WEB_ENABLED": "lookup.whois_web_enabled", "WHOICE_WHOIS_FOLLOW_LIMIT": "lookup.whois_follow_limit",
	"WHOICE_DNS_FIRST_SUFFIXES": "lookup.dns_first_suffixes",
	"WHOICE_LOOKUP_FAST_RESPONSE": "lookup.fast_response",
	"WHOICE_ENRICH_DNS": "dns.enabled", "WHOICE_DNS_TIMEOUT": "dns.timeout",
	"WHOICE_DNS_IPV4_RESOLVERS": "dns.ipv4_resolvers", "WHOICE_DNS_IPV6_RESOLVERS": "dns.ipv6_resolvers",
	"WHOICE_DNS_DOH_RESOLVERS": "dns.doh_resolvers", "WHOICE_DNS_FILTER_FAKE_IP": "dns.filter_fake_ip",
	"WHOICE_ENRICH_DNSVIZ": "dns.dnsviz_enabled",
	"WHOICE_ENRICH_EPP": "enrichment.epp", "WHOICE_ENRICH_BRANDS": "enrichment.brands",
	"WHOICE_ENRICH_REGISTRAR": "enrichment.registrar", "WHOICE_ENRICH_PRICING": "enrichment.pricing",
	"WHOICE_ENRICH_MOZ": "enrichment.moz", "WHOICE_PRICING_CACHE_TTL": "enrichment.pricing_cache_ttl",
	"WHOICE_FX_CACHE_TTL": "enrichment.fx_cache_ttl",
	"WHOICE_AI_ENABLED": "ai.enabled", "WHOICE_AI_PROVIDER": "ai.provider", "WHOICE_AI_BASE_URL": "ai.base_url",
	"WHOICE_AI_API_KEY": "ai.api_key", "WHOICE_AI_MODEL": "ai.model", "WHOICE_AI_TIMEOUT": "ai.timeout",
	"WHOICE_AI_CACHE_TTL": "ai.cache_ttl", "WHOICE_AI_MAX_INPUT_CHARS": "ai.max_input_chars",
	"WHOICE_AI_MIN_CONFIDENCE": "ai.min_confidence", "WHOICE_AI_TEMPERATURE": "ai.temperature",
	"WHOICE_AI_MAX_OUTPUT_TOKENS": "ai.max_output_tokens", "WHOICE_AI_MAX_ATTEMPTS": "ai.max_attempts",
	"WHOICE_AI_IGNORE_SUFFIXES": "ai.ignore_suffixes", "WHOICE_AI_IGNORE_REGEX": "ai.ignore_regex",
	"WHOICE_AI_PROMPT": "ai.prompt",
	"WHOICE_ICP_ENABLED": "icp.enabled", "WHOICE_ICP_AUTO_QUERY": "icp.auto_query", "WHOICE_ICP_TIMEOUT": "icp.timeout",
	"WHOICE_ICP_CACHE_TTL": "icp.cache_ttl", "WHOICE_ICP_NEGATIVE_CACHE_TTL": "icp.negative_cache_ttl",
	"WHOICE_ICP_ERROR_CACHE_TTL": "icp.error_cache_ttl", "WHOICE_ICP_BASE_URL": "icp.base_url",
	"WHOICE_ICP_UPSTREAM_URL": "icp.upstream_url", "WHOICE_ICP_CAPTCHA_ENABLED": "icp.captcha_enabled",
	"WHOICE_ICP_CAPTCHA_RETRIES": "icp.captcha_retries", "WHOICE_ICP_SIGN": "icp.sign",
	"WHOICE_ICP_PAGE_SIZE": "icp.page_size", "WHOICE_ICP_BLOCKLIST": "icp.blocklist",
	"WHOICE_RATE_LIMIT_ENABLED": "rate_limit.enabled", "WHOICE_RATE_LIMIT_ANON": "rate_limit.anon",
	"WHOICE_METRICS_ENABLED": "metrics.enabled",
	"WHOICE_OBSERVABILITY_REPORTER": "observability.reporter", "WHOICE_OBSERVABILITY_WEBHOOK_URL": "observability.webhook_url",
	"WHOICE_OBSERVABILITY_TIMEOUT": "observability.timeout",
	"WHOICE_PSL_AUTO_UPDATE": "public_suffix.auto_update", "WHOICE_PSL_URL": "public_suffix.url",
	"WHOICE_PSL_UPDATE_TIMEOUT": "public_suffix.update_timeout",
}

// EnvLockedFields lists settings paths whose value currently comes from the environment.
// The panel shows them read-only because file edits would not take effect.
func EnvLockedFields() map[string]string {
	locked := map[string]string{}
	for env, path := range envBindings {
		if strings.TrimSpace(os.Getenv(env)) != "" {
			locked[path] = env
		}
	}
	return locked
}

// Secret settings are never returned to the browser; the panel only learns whether they are set.
type SecretState struct {
	SitePassword      bool `json:"site_password"`
	APITokens         int  `json:"api_tokens"`
	AIAPIKey          bool `json:"ai_api_key"`
	ObservabilityHook bool `json:"webhook_url"`
}

func SecretsOf(cfg Config) SecretState {
	return SecretState{
		SitePassword:      cfg.SitePassword != "",
		APITokens:         len(cleanList(cfg.APITokens)),
		AIAPIKey:          cfg.AIAPIKey != "",
		ObservabilityHook: cfg.ReporterWebhookURL != "",
	}
}

// SettingsView returns cfg in file shape with secrets removed.
func SettingsView(cfg Config) FileConfig {
	str := func(value string) *string { return &value }
	boolean := func(value bool) *bool { return &value }
	integer := func(value int) *int { return &value }
	float := func(value float64) *float64 { return &value }
	list := func(values []string) []string {
		if values == nil {
			return []string{}
		}
		return append([]string{}, values...)
	}
	prompt := cfg.AIPrompt
	if strings.TrimSpace(prompt) == "" {
		prompt = DefaultAIPrompt
	}
	return FileConfig{
		Server: &ServerConfig{
			Addr: str(cfg.Addr), DataDir: str(cfg.DataDir), TrustProxy: boolean(cfg.TrustProxy),
			AllowCustomServers: boolean(cfg.AllowCustomServers), AllowPrivateServers: boolean(cfg.AllowPrivateServers),
		},
		API: &APIConfig{
			Enabled: boolean(cfg.APIEnabled), IPAllowlist: list(cfg.APIIPAllowlist),
			Endpoints: &APIEndpointsConfig{
				Health: boolean(cfg.APIHealthEnabled), Version: boolean(cfg.APIVersionEnabled),
				Capabilities: boolean(cfg.APICapabilitiesEnabled), Metrics: boolean(cfg.APIMetricsEnabled),
				Lookup: boolean(cfg.APILookupEnabled), LookupAI: boolean(cfg.APILookupAIEnabled),
				LookupEnrich: boolean(cfg.APILookupEnrichEnabled), ICP: boolean(cfg.APIICPEnabled),
				Admin: boolean(cfg.APIAdminEnabled), AdminStatus: boolean(cfg.APIAdminStatusEnabled),
				AdminConfig: boolean(cfg.APIAdminConfigEnabled),
			},
		},
		Auth: &AuthConfig{Mode: str(cfg.AuthMode)},
		Lookup: &LookupConfig{
			Timeout: str(FormatDuration(cfg.LookupTimeout)), ProviderTimeout: str(FormatDuration(cfg.ProviderTimeout)),
			RDAPEnabled: boolean(cfg.RDAPEnabled), WHOISEnabled: boolean(cfg.WHOISEnabled),
			WHOISWebEnabled: boolean(cfg.WHOISWebEnabled), WHOISFollowLimit: integer(cfg.WHOISFollowLimit),
			DNSFirstSuffixes: list(cfg.DNSFirstSuffixes),
			FastResponse: boolean(cfg.LookupFastResponse),
		},
		DNS: &DNSConfig{
			Enabled: boolean(cfg.EnrichDNS), Timeout: str(FormatDuration(cfg.DNSTimeout)),
			IPv4Resolvers: list(cfg.DNSIPv4Resolvers), IPv6Resolvers: list(cfg.DNSIPv6Resolvers),
			DoHResolvers: list(cfg.DNSDoHResolvers), FilterFakeIP: boolean(cfg.DNSFilterFakeIP),
			DNSVizEnabled: boolean(cfg.EnrichDNSViz),
		},
		Enrichment: &EnrichmentConfig{
			EPP: boolean(cfg.EnrichEPP), Brands: boolean(cfg.EnrichBrands), Registrar: boolean(cfg.EnrichRegistrar),
			Pricing: boolean(cfg.EnrichPricing), Moz: boolean(cfg.EnrichMoz),
			PricingCacheTTL: str(FormatCacheDuration(cfg.PricingCacheTTL)),
			FXCacheTTL: str(FormatCacheDuration(cfg.FXCacheTTL)),
		},
		AI: &AIConfig{
			Enabled: boolean(cfg.AIEnabled), Provider: str(cfg.AIProvider), BaseURL: str(cfg.AIBaseURL),
			Model: str(cfg.AIModel), Timeout: str(FormatDuration(cfg.AITimeout)),
			CacheTTL: str(FormatCacheDuration(cfg.AICacheTTL)), MaxInputChars: integer(cfg.AIMaxInputChars),
			MinConfidence: float(cfg.AIMinConfidence), Temperature: float(cfg.AITemperature),
			MaxOutputTokens: integer(cfg.AIMaxOutputTokens), MaxAttempts: integer(cfg.AIMaxAttempts),
			IgnoreSuffixes: list(cfg.AIIgnoreSuffixes), IgnoreRegex: list(cfg.AIIgnoreRegex), Prompt: str(prompt),
		},
		ICP: &ICPConfig{
			Enabled: boolean(cfg.ICPEnabled), AutoQuery: boolean(cfg.ICPAutoQuery), Timeout: str(FormatDuration(cfg.ICPTimeout)),
			CacheTTL: str(FormatCacheDuration(cfg.ICPCacheTTL)), NegativeCacheTTL: str(FormatCacheDuration(cfg.ICPNegativeCacheTTL)),
			ErrorCacheTTL: str(FormatCacheDuration(cfg.ICPErrorCacheTTL)), BaseURL: str(cfg.ICPBaseURL),
			UpstreamURL: str(cfg.ICPUpstreamURL), CaptchaEnabled: boolean(cfg.ICPCaptchaEnabled),
			CaptchaRetries: integer(cfg.ICPCaptchaRetries), PageSize: integer(cfg.ICPPageSize), Blocklist: list(cfg.ICPBlocklist),
		},
		RateLimit:     &RateLimitConfig{Enabled: boolean(cfg.RateLimitEnabled), Anon: str(cfg.RateLimitAnon)},
		Metrics:       &MetricsConfig{Enabled: boolean(cfg.MetricsEnabled)},
		Observability: &ObservabilityConfig{Reporter: str(cfg.Reporter), Timeout: str(FormatDuration(cfg.ReporterTimeout))},
		PSL: &PSLConfig{
			AutoUpdate: boolean(cfg.PSLAutoUpdate), URL: str(cfg.PSLURL), UpdateTimeout: str(FormatDuration(cfg.PSLUpdateTimeout)),
		},
	}
}

// WriteFile renders cfg and replaces path atomically. The previous file is kept as path.bak.
func WriteFile(path string, cfg Config) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("no config file path is active")
	}
	body := RenderFile(cfg, cfg.DataDir)
	dir := filepath.Dir(path)
	if previous, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", previous, 0o600); err != nil {
			return fmt.Errorf("back up config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".whoice-*.toml")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// A config file bind-mounted on its own cannot be replaced by rename; write it in place.
		if writeErr := os.WriteFile(path, []byte(body), 0o600); writeErr != nil {
			return fmt.Errorf("replace config: %v; direct write: %w", err, writeErr)
		}
	}
	return nil
}
