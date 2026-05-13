package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Config struct {
	Addr                string
	LookupTimeout       time.Duration
	ProviderTimeout     time.Duration
	DataDir             string
	AuthMode            string
	SitePassword        string
	APITokens           []string
	RDAPEnabled         bool
	WHOISEnabled        bool
	WHOISWebEnabled     bool
	WHOISFollowLimit    int
	AllowCustomServers  bool
	AllowPrivateServers bool
	EnrichEPP           bool
	EnrichBrands        bool
	EnrichRegistrar     bool
	EnrichDNS           bool
	DNSTimeout          time.Duration
	DNSIPv4Resolvers    []string
	DNSIPv6Resolvers    []string
	DNSDoHResolvers     []string
	DNSFilterFakeIP     bool
	EnrichDNSViz        bool
	EnrichPricing       bool
	EnrichMoz           bool
	AIEnabled           bool
	AIProvider          string
	AIBaseURL           string
	AIAPIKey            string
	AIModel             string
	AITimeout           time.Duration
	AICacheTTL          time.Duration
	AIMaxInputChars     int
	AIMinConfidence     float64
	AITemperature       float64
	AIMaxOutputTokens   int
	AIMaxAttempts       int
	AIPrompt            string
	ICPEnabled          bool
	ICPAutoQuery        bool
	ICPTimeout          time.Duration
	ICPCacheTTL         time.Duration
	ICPNegativeCacheTTL time.Duration
	ICPErrorCacheTTL    time.Duration
	ICPBaseURL          string
	ICPUpstreamURL      string
	ICPCaptchaEnabled   bool
	ICPCaptchaRetries   int
	ICPSign             string
	ICPPageSize         int
	ICPBlocklist        []string
	RateLimitEnabled    bool
	RateLimitAnon       string
	TrustProxy          bool
	MetricsEnabled      bool
	Reporter            string
	ReporterWebhookURL  string
	ReporterTimeout     time.Duration
	PSLAutoUpdate       bool
	PSLURL              string
	PSLUpdateTimeout    time.Duration
	ConfigPath          string
	ConfigCreated       bool
}

func Load() Config {
	cfg, err := LoadWithError()
	if err != nil {
		panic(err)
	}
	return cfg
}

func LoadWithError() (Config, error) {
	cfg := Default()
	configPath, autoCreate := configPathFromEnv(cfg.DataDir)
	if configPath != "" {
		created := false
		if autoCreate {
			var err error
			created, err = EnsureDefaultFile(configPath)
			if err != nil {
				return cfg, err
			}
		}
		cfg.ConfigPath = configPath
		cfg.ConfigCreated = created
		if err := applyFile(&cfg, configPath); err != nil {
			return cfg, err
		}
	}
	applyEnv(&cfg)
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = configPath
	}
	return cfg, nil
}

func Default() Config {
	return Config{
		Addr:                ":8080",
		LookupTimeout:       15 * time.Second,
		ProviderTimeout:     10 * time.Second,
		DataDir:             "data",
		AuthMode:            "none",
		RDAPEnabled:         true,
		WHOISEnabled:        true,
		WHOISFollowLimit:    1,
		EnrichEPP:           true,
		EnrichRegistrar:     true,
		EnrichDNS:           true,
		DNSTimeout:          3 * time.Second,
		DNSIPv4Resolvers:    parseList("1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,180.184.1.1,180.184.2.2"),
		DNSIPv6Resolvers:    parseList("2606:4700:4700::1111,2606:4700:4700::1001,2001:4860:4860::8888,2001:4860:4860::8844"),
		DNSDoHResolvers:     parseList("https://cloudflare-dns.com/dns-query,https://dns.google/resolve,https://doh.pub/dns-query,https://dns.alidns.com/dns-query"),
		DNSFilterFakeIP:     true,
		EnrichDNSViz:        true,
		AIProvider:          "openai-compatible",
		AITimeout:           8 * time.Second,
		AICacheTTL:          168 * time.Hour,
		AIMaxInputChars:     16000,
		AIMinConfidence:     0.68,
		AIMaxOutputTokens:   700,
		AIMaxAttempts:       3,
		ICPEnabled:          true,
		ICPTimeout:          8 * time.Second,
		ICPCacheTTL:         72 * time.Hour,
		ICPNegativeCacheTTL: 12 * time.Hour,
		ICPErrorCacheTTL:    10 * time.Minute,
		ICPBaseURL:          "https://hlwicpfwc.miit.gov.cn/icpproject_query/api",
		ICPCaptchaEnabled:   true,
		ICPCaptchaRetries:   3,
		ICPSign:             "eyJ0eXBlIjozLCJleHREYXRhIjp7InZhZnljb2RlX2ltYWdlX2tleSI6IjUyZWI1ZTcyODViNzRmNWJhM2YwYzBkNTg0YTg3NmVmIn0sImUiOjE3NTY5NzAyNDg4MjN9.Ngpkwn4T7sQoQF9pCk_sQQpH61wQUEKnK2sQ8hDIq-Q",
		ICPPageSize:         10,
		RateLimitAnon:       "60/min",
		MetricsEnabled:      true,
		Reporter:            "none",
		ReporterTimeout:     2 * time.Second,
		PSLURL:              "https://publicsuffix.org/list/public_suffix_list.dat",
		PSLUpdateTimeout:    5 * time.Second,
	}
}

func (c Config) DNSServers() []string {
	servers := make([]string, 0, len(c.DNSIPv4Resolvers)+len(c.DNSIPv6Resolvers))
	servers = append(servers, c.DNSIPv4Resolvers...)
	servers = append(servers, c.DNSIPv6Resolvers...)
	return servers
}

func (c Config) Capabilities() model.Capabilities {
	return model.Capabilities{
		RDAP:          c.RDAPEnabled,
		WHOIS:         c.WHOISEnabled,
		WHOISWeb:      c.WHOISWebEnabled,
		CustomServers: c.AllowCustomServers,
		Auth:          c.AuthMode,
		RateLimit:     c.RateLimitEnabled,
		ICPAutoQuery:  c.ICPAutoQuery,
		Enrichment: map[string]bool{
			"epp":       c.EnrichEPP,
			"brands":    c.EnrichBrands,
			"registrar": c.EnrichRegistrar,
			"dns":       c.EnrichDNS,
			"dnsviz":    c.EnrichDNSViz,
			"pricing":   c.EnrichPricing,
			"moz":       c.EnrichMoz,
			"ai":        c.AIEnabled,
			"icp":       c.ICPEnabled,
		},
	}
}

type fileConfig struct {
	Server        *serverConfig        `toml:"server"`
	Auth          *authConfig          `toml:"auth"`
	Lookup        *lookupConfig        `toml:"lookup"`
	DNS           *dnsConfig           `toml:"dns"`
	Enrichment    *enrichmentConfig    `toml:"enrichment"`
	AI            *aiConfig            `toml:"ai"`
	ICP           *icpConfig           `toml:"icp"`
	RateLimit     *rateLimitConfig     `toml:"rate_limit"`
	Metrics       *metricsConfig       `toml:"metrics"`
	Observability *observabilityConfig `toml:"observability"`
	PSL           *pslConfig           `toml:"public_suffix"`
}

type serverConfig struct {
	Addr                *string `toml:"addr"`
	DataDir             *string `toml:"data_dir"`
	TrustProxy          *bool   `toml:"trust_proxy"`
	AllowCustomServers  *bool   `toml:"allow_custom_servers"`
	AllowPrivateServers *bool   `toml:"allow_private_servers"`
}

type authConfig struct {
	Mode         *string  `toml:"mode"`
	SitePassword *string  `toml:"site_password"`
	APITokens    []string `toml:"api_tokens"`
}

type lookupConfig struct {
	Timeout          *string `toml:"timeout"`
	ProviderTimeout  *string `toml:"provider_timeout"`
	RDAPEnabled      *bool   `toml:"rdap_enabled"`
	WHOISEnabled     *bool   `toml:"whois_enabled"`
	WHOISWebEnabled  *bool   `toml:"whois_web_enabled"`
	WHOISFollowLimit *int    `toml:"whois_follow_limit"`
}

type dnsConfig struct {
	Enabled       *bool    `toml:"enabled"`
	Timeout       *string  `toml:"timeout"`
	IPv4Resolvers []string `toml:"ipv4_resolvers"`
	IPv6Resolvers []string `toml:"ipv6_resolvers"`
	DoHResolvers  []string `toml:"doh_resolvers"`
	FilterFakeIP  *bool    `toml:"filter_fake_ip"`
	DNSVizEnabled *bool    `toml:"dnsviz_enabled"`
}

type enrichmentConfig struct {
	EPP       *bool `toml:"epp"`
	Brands    *bool `toml:"brands"`
	Registrar *bool `toml:"registrar"`
	Pricing   *bool `toml:"pricing"`
	Moz       *bool `toml:"moz"`
}

type aiConfig struct {
	Enabled         *bool    `toml:"enabled"`
	Provider        *string  `toml:"provider"`
	BaseURL         *string  `toml:"base_url"`
	APIKey          *string  `toml:"api_key"`
	Model           *string  `toml:"model"`
	Timeout         *string  `toml:"timeout"`
	CacheTTL        *string  `toml:"cache_ttl"`
	MaxInputChars   *int     `toml:"max_input_chars"`
	MinConfidence   *float64 `toml:"min_confidence"`
	Temperature     *float64 `toml:"temperature"`
	MaxOutputTokens *int     `toml:"max_output_tokens"`
	MaxAttempts     *int     `toml:"max_attempts"`
	Prompt          *string  `toml:"prompt"`
}

type icpConfig struct {
	Enabled          *bool    `toml:"enabled"`
	AutoQuery        *bool    `toml:"auto_query"`
	Timeout          *string  `toml:"timeout"`
	CacheTTL         *string  `toml:"cache_ttl"`
	NegativeCacheTTL *string  `toml:"negative_cache_ttl"`
	ErrorCacheTTL    *string  `toml:"error_cache_ttl"`
	BaseURL          *string  `toml:"base_url"`
	UpstreamURL      *string  `toml:"upstream_url"`
	CaptchaEnabled   *bool    `toml:"captcha_enabled"`
	CaptchaRetries   *int     `toml:"captcha_retries"`
	Sign             *string  `toml:"sign"`
	PageSize         *int     `toml:"page_size"`
	Blocklist        []string `toml:"blocklist"`
}

type rateLimitConfig struct {
	Enabled *bool   `toml:"enabled"`
	Anon    *string `toml:"anon"`
}

type metricsConfig struct {
	Enabled *bool `toml:"enabled"`
}

type observabilityConfig struct {
	Reporter   *string `toml:"reporter"`
	WebhookURL *string `toml:"webhook_url"`
	Timeout    *string `toml:"timeout"`
}

type pslConfig struct {
	AutoUpdate    *bool   `toml:"auto_update"`
	URL           *string `toml:"url"`
	UpdateTimeout *string `toml:"update_timeout"`
}

func configPathFromEnv(dataDir string) (string, bool) {
	autoCreate := !strings.EqualFold(strings.TrimSpace(os.Getenv("WHOICE_CONFIG_AUTO_CREATE")), "false")
	if value, ok := os.LookupEnv("WHOICE_CONFIG"); ok {
		return strings.TrimSpace(value), autoCreate
	}
	if !autoCreate {
		return "", false
	}
	return filepath.Join(envString("WHOICE_DATA_DIR", dataDir), "whoice.toml"), true
}

func EnsureDefaultFile(path string) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, nil
	}
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat config file %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create config directory %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(DefaultTemplate(filepath.Dir(path))), 0o600); err != nil {
		return false, fmt.Errorf("create default config %s: %w", path, err)
	}
	return true, nil
}

func applyFile(cfg *Config, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file %s: %w", path, err)
	}
	var file fileConfig
	if err := toml.Unmarshal(body, &file); err != nil {
		return fmt.Errorf("parse config file %s: %w", path, err)
	}
	file.apply(cfg)
	return nil
}

func (f fileConfig) apply(cfg *Config) {
	if f.Server != nil {
		setString(&cfg.Addr, f.Server.Addr)
		setString(&cfg.DataDir, f.Server.DataDir)
		setBool(&cfg.TrustProxy, f.Server.TrustProxy)
		setBool(&cfg.AllowCustomServers, f.Server.AllowCustomServers)
		setBool(&cfg.AllowPrivateServers, f.Server.AllowPrivateServers)
	}
	if f.Auth != nil {
		setString(&cfg.AuthMode, f.Auth.Mode)
		setString(&cfg.SitePassword, f.Auth.SitePassword)
		setList(&cfg.APITokens, f.Auth.APITokens)
	}
	if f.Lookup != nil {
		setDuration(&cfg.LookupTimeout, f.Lookup.Timeout)
		setDuration(&cfg.ProviderTimeout, f.Lookup.ProviderTimeout)
		setBool(&cfg.RDAPEnabled, f.Lookup.RDAPEnabled)
		setBool(&cfg.WHOISEnabled, f.Lookup.WHOISEnabled)
		setBool(&cfg.WHOISWebEnabled, f.Lookup.WHOISWebEnabled)
		setInt(&cfg.WHOISFollowLimit, f.Lookup.WHOISFollowLimit)
	}
	if f.DNS != nil {
		setBool(&cfg.EnrichDNS, f.DNS.Enabled)
		setDuration(&cfg.DNSTimeout, f.DNS.Timeout)
		setList(&cfg.DNSIPv4Resolvers, f.DNS.IPv4Resolvers)
		setList(&cfg.DNSIPv6Resolvers, f.DNS.IPv6Resolvers)
		setList(&cfg.DNSDoHResolvers, f.DNS.DoHResolvers)
		setBool(&cfg.DNSFilterFakeIP, f.DNS.FilterFakeIP)
		setBool(&cfg.EnrichDNSViz, f.DNS.DNSVizEnabled)
	}
	if f.Enrichment != nil {
		setBool(&cfg.EnrichEPP, f.Enrichment.EPP)
		setBool(&cfg.EnrichBrands, f.Enrichment.Brands)
		setBool(&cfg.EnrichRegistrar, f.Enrichment.Registrar)
		setBool(&cfg.EnrichPricing, f.Enrichment.Pricing)
		setBool(&cfg.EnrichMoz, f.Enrichment.Moz)
	}
	if f.AI != nil {
		setBool(&cfg.AIEnabled, f.AI.Enabled)
		setString(&cfg.AIProvider, f.AI.Provider)
		setString(&cfg.AIBaseURL, f.AI.BaseURL)
		setString(&cfg.AIAPIKey, f.AI.APIKey)
		setString(&cfg.AIModel, f.AI.Model)
		setDuration(&cfg.AITimeout, f.AI.Timeout)
		setCacheDuration(&cfg.AICacheTTL, f.AI.CacheTTL)
		setInt(&cfg.AIMaxInputChars, f.AI.MaxInputChars)
		setFloat(&cfg.AIMinConfidence, f.AI.MinConfidence)
		setFloat(&cfg.AITemperature, f.AI.Temperature)
		setInt(&cfg.AIMaxOutputTokens, f.AI.MaxOutputTokens)
		setInt(&cfg.AIMaxAttempts, f.AI.MaxAttempts)
		setString(&cfg.AIPrompt, f.AI.Prompt)
	}
	if f.ICP != nil {
		setBool(&cfg.ICPEnabled, f.ICP.Enabled)
		setBool(&cfg.ICPAutoQuery, f.ICP.AutoQuery)
		setDuration(&cfg.ICPTimeout, f.ICP.Timeout)
		setCacheDuration(&cfg.ICPCacheTTL, f.ICP.CacheTTL)
		setCacheDuration(&cfg.ICPNegativeCacheTTL, f.ICP.NegativeCacheTTL)
		setCacheDuration(&cfg.ICPErrorCacheTTL, f.ICP.ErrorCacheTTL)
		setString(&cfg.ICPBaseURL, f.ICP.BaseURL)
		setString(&cfg.ICPUpstreamURL, f.ICP.UpstreamURL)
		setBool(&cfg.ICPCaptchaEnabled, f.ICP.CaptchaEnabled)
		setInt(&cfg.ICPCaptchaRetries, f.ICP.CaptchaRetries)
		setString(&cfg.ICPSign, f.ICP.Sign)
		setInt(&cfg.ICPPageSize, f.ICP.PageSize)
		setList(&cfg.ICPBlocklist, f.ICP.Blocklist)
	}
	if f.RateLimit != nil {
		setBool(&cfg.RateLimitEnabled, f.RateLimit.Enabled)
		setString(&cfg.RateLimitAnon, f.RateLimit.Anon)
	}
	if f.Metrics != nil {
		setBool(&cfg.MetricsEnabled, f.Metrics.Enabled)
	}
	if f.Observability != nil {
		setString(&cfg.Reporter, f.Observability.Reporter)
		setString(&cfg.ReporterWebhookURL, f.Observability.WebhookURL)
		setDuration(&cfg.ReporterTimeout, f.Observability.Timeout)
	}
	if f.PSL != nil {
		setBool(&cfg.PSLAutoUpdate, f.PSL.AutoUpdate)
		setString(&cfg.PSLURL, f.PSL.URL)
		setDuration(&cfg.PSLUpdateTimeout, f.PSL.UpdateTimeout)
	}
}

func applyEnv(cfg *Config) {
	envStringInto(&cfg.Addr, "WHOICE_API_ADDR")
	envDurationInto(&cfg.LookupTimeout, "WHOICE_LOOKUP_TIMEOUT")
	envDurationInto(&cfg.ProviderTimeout, "WHOICE_PROVIDER_TIMEOUT")
	envStringInto(&cfg.DataDir, "WHOICE_DATA_DIR")
	envStringInto(&cfg.AuthMode, "WHOICE_AUTH_MODE")
	envStringInto(&cfg.SitePassword, "WHOICE_SITE_PASSWORD")
	envListInto(&cfg.APITokens, "WHOICE_API_TOKENS")
	envBoolInto(&cfg.RDAPEnabled, "WHOICE_RDAP_ENABLED")
	envBoolInto(&cfg.WHOISEnabled, "WHOICE_WHOIS_ENABLED")
	envBoolInto(&cfg.WHOISWebEnabled, "WHOICE_WHOIS_WEB_ENABLED")
	envIntInto(&cfg.WHOISFollowLimit, "WHOICE_WHOIS_FOLLOW_LIMIT")
	envBoolInto(&cfg.AllowCustomServers, "WHOICE_ALLOW_CUSTOM_SERVERS")
	envBoolInto(&cfg.AllowPrivateServers, "WHOICE_ALLOW_PRIVATE_SERVERS")
	envBoolInto(&cfg.EnrichEPP, "WHOICE_ENRICH_EPP")
	envBoolInto(&cfg.EnrichBrands, "WHOICE_ENRICH_BRANDS")
	envBoolInto(&cfg.EnrichRegistrar, "WHOICE_ENRICH_REGISTRAR")
	envBoolInto(&cfg.EnrichDNS, "WHOICE_ENRICH_DNS")
	envDurationInto(&cfg.DNSTimeout, "WHOICE_DNS_TIMEOUT")
	envListInto(&cfg.DNSIPv4Resolvers, "WHOICE_DNS_IPV4_RESOLVERS")
	envListInto(&cfg.DNSIPv6Resolvers, "WHOICE_DNS_IPV6_RESOLVERS")
	envListInto(&cfg.DNSDoHResolvers, "WHOICE_DNS_DOH_RESOLVERS")
	envBoolInto(&cfg.DNSFilterFakeIP, "WHOICE_DNS_FILTER_FAKE_IP")
	envBoolInto(&cfg.EnrichDNSViz, "WHOICE_ENRICH_DNSVIZ")
	envBoolInto(&cfg.EnrichPricing, "WHOICE_ENRICH_PRICING")
	envBoolInto(&cfg.EnrichMoz, "WHOICE_ENRICH_MOZ")
	envBoolInto(&cfg.AIEnabled, "WHOICE_AI_ENABLED")
	envStringInto(&cfg.AIProvider, "WHOICE_AI_PROVIDER")
	envStringInto(&cfg.AIBaseURL, "WHOICE_AI_BASE_URL")
	envStringInto(&cfg.AIAPIKey, "WHOICE_AI_API_KEY")
	envStringInto(&cfg.AIModel, "WHOICE_AI_MODEL")
	envDurationInto(&cfg.AITimeout, "WHOICE_AI_TIMEOUT")
	envCacheDurationInto(&cfg.AICacheTTL, "WHOICE_AI_CACHE_TTL")
	envIntInto(&cfg.AIMaxInputChars, "WHOICE_AI_MAX_INPUT_CHARS")
	envFloatInto(&cfg.AIMinConfidence, "WHOICE_AI_MIN_CONFIDENCE")
	envFloatInto(&cfg.AITemperature, "WHOICE_AI_TEMPERATURE")
	envIntInto(&cfg.AIMaxOutputTokens, "WHOICE_AI_MAX_OUTPUT_TOKENS")
	envIntInto(&cfg.AIMaxAttempts, "WHOICE_AI_MAX_ATTEMPTS")
	envStringInto(&cfg.AIPrompt, "WHOICE_AI_PROMPT")
	envBoolInto(&cfg.ICPEnabled, "WHOICE_ICP_ENABLED")
	envBoolInto(&cfg.ICPAutoQuery, "WHOICE_ICP_AUTO_QUERY")
	envDurationInto(&cfg.ICPTimeout, "WHOICE_ICP_TIMEOUT")
	envCacheDurationInto(&cfg.ICPCacheTTL, "WHOICE_ICP_CACHE_TTL")
	envCacheDurationInto(&cfg.ICPNegativeCacheTTL, "WHOICE_ICP_NEGATIVE_CACHE_TTL")
	envCacheDurationInto(&cfg.ICPErrorCacheTTL, "WHOICE_ICP_ERROR_CACHE_TTL")
	envStringInto(&cfg.ICPBaseURL, "WHOICE_ICP_BASE_URL")
	envStringInto(&cfg.ICPUpstreamURL, "WHOICE_ICP_UPSTREAM_URL")
	envBoolInto(&cfg.ICPCaptchaEnabled, "WHOICE_ICP_CAPTCHA_ENABLED")
	envIntInto(&cfg.ICPCaptchaRetries, "WHOICE_ICP_CAPTCHA_RETRIES")
	envStringInto(&cfg.ICPSign, "WHOICE_ICP_SIGN")
	envIntInto(&cfg.ICPPageSize, "WHOICE_ICP_PAGE_SIZE")
	envListInto(&cfg.ICPBlocklist, "WHOICE_ICP_BLOCKLIST")
	envBoolInto(&cfg.RateLimitEnabled, "WHOICE_RATE_LIMIT_ENABLED")
	envStringInto(&cfg.RateLimitAnon, "WHOICE_RATE_LIMIT_ANON")
	envBoolInto(&cfg.TrustProxy, "WHOICE_TRUST_PROXY")
	envBoolInto(&cfg.MetricsEnabled, "WHOICE_METRICS_ENABLED")
	envStringInto(&cfg.Reporter, "WHOICE_OBSERVABILITY_REPORTER")
	envStringInto(&cfg.ReporterWebhookURL, "WHOICE_OBSERVABILITY_WEBHOOK_URL")
	envDurationInto(&cfg.ReporterTimeout, "WHOICE_OBSERVABILITY_TIMEOUT")
	envBoolInto(&cfg.PSLAutoUpdate, "WHOICE_PSL_AUTO_UPDATE")
	envStringInto(&cfg.PSLURL, "WHOICE_PSL_URL")
	envDurationInto(&cfg.PSLUpdateTimeout, "WHOICE_PSL_UPDATE_TIMEOUT")
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envStringInto(target *string, key string) {
	if value, ok := os.LookupEnv(key); ok {
		*target = strings.TrimSpace(value)
	}
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBoolInto(target *bool, key string) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	parsed, err := strconv.ParseBool(value)
	if err == nil {
		*target = parsed
	}
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDurationInto(target *time.Duration, key string) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	parsed, err := time.ParseDuration(value)
	if err == nil {
		*target = parsed
	}
}

func envCacheDuration(key string, fallback time.Duration) time.Duration {
	return parseCacheDuration(os.Getenv(key), fallback)
}

func envCacheDurationInto(target *time.Duration, key string) {
	if value, ok := os.LookupEnv(key); ok {
		*target = parseCacheDuration(value, *target)
	}
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envIntInto(target *int, key string) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	parsed, err := strconv.Atoi(value)
	if err == nil {
		*target = parsed
	}
}

func envFloat(key string, fallback float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloatInto(target *float64, key string) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err == nil {
		*target = parsed
	}
}

func envList(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	return parseList(value)
}

func envListInto(target *[]string, key string) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	if isNoneList(value) {
		*target = nil
		return
	}
	*target = parseList(value)
}

func envListWithDefault(key, fallback string) []string {
	value, ok := os.LookupEnv(key)
	if !ok {
		value = fallback
	}
	if isNoneList(value) {
		return nil
	}
	return parseList(value)
}

func parseList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func isNoneList(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none", "off", "false", "disable", "disabled", "-":
		return true
	default:
		return false
	}
}

func setString(target *string, value *string) {
	if value != nil {
		*target = strings.TrimSpace(*value)
	}
}

func setBool(target *bool, value *bool) {
	if value != nil {
		*target = *value
	}
}

func setInt(target *int, value *int) {
	if value != nil {
		*target = *value
	}
}

func setFloat(target *float64, value *float64) {
	if value != nil {
		*target = *value
	}
}

func setList(target *[]string, values []string) {
	if values != nil {
		*target = cleanList(values)
	}
}

func setDuration(target *time.Duration, value *string) {
	if value == nil {
		return
	}
	if parsed, err := time.ParseDuration(strings.TrimSpace(*value)); err == nil {
		*target = parsed
	}
}

func setCacheDuration(target *time.Duration, value *string) {
	if value != nil {
		*target = parseCacheDuration(*value, *target)
	}
}

func parseCacheDuration(value string, fallback time.Duration) time.Duration {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	switch value {
	case "0", "0s", "none", "off", "false", "disable", "disabled", "no-cache", "nocache":
		return 0
	case "-1", "forever", "permanent", "infinite", "infinity", "inf", "never":
		return -1
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	if parsed < 0 {
		return -1
	}
	return parsed
}

func cleanList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
