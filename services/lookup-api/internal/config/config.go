package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pelletier/go-toml/v2"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Config struct {
	Addr                   string
	LookupTimeout          time.Duration
	ProviderTimeout        time.Duration
	DataDir                string
	APIEnabled             bool
	APIIPAllowlist         []string
	APIHealthEnabled       bool
	APIVersionEnabled      bool
	APICapabilitiesEnabled bool
	APIMetricsEnabled      bool
	APILookupEnabled       bool
	APILookupAIEnabled     bool
	APILookupEnrichEnabled bool
	APIICPEnabled          bool
	APIAdminEnabled        bool
	APIAdminStatusEnabled  bool
	APIAdminConfigEnabled  bool
	AuthMode               string
	SitePassword           string
	APITokens              []string
	RDAPEnabled            bool
	WHOISEnabled           bool
	WHOISWebEnabled        bool
	WHOISFollowLimit       int
	LookupFastResponse     bool
	AllowCustomServers     bool
	AllowPrivateServers    bool
	EnrichEPP              bool
	EnrichBrands           bool
	EnrichRegistrar        bool
	EnrichDNS              bool
	DNSTimeout             time.Duration
	DNSIPv4Resolvers       []string
	DNSIPv6Resolvers       []string
	DNSDoHResolvers        []string
	DNSFilterFakeIP        bool
	EnrichDNSViz           bool
	EnrichPricing          bool
	EnrichMoz              bool
	AIEnabled              bool
	AIProvider             string
	AIBaseURL              string
	AIAPIKey               string
	AIModel                string
	AITimeout              time.Duration
	AICacheTTL             time.Duration
	AIMaxInputChars        int
	AIMinConfidence        float64
	AITemperature          float64
	AIMaxOutputTokens      int
	AIMaxAttempts          int
	AIIgnoreSuffixes       []string
	AIIgnoreRegex          []string
	AIPrompt               string
	ICPEnabled             bool
	ICPAutoQuery           bool
	ICPTimeout             time.Duration
	ICPCacheTTL            time.Duration
	ICPNegativeCacheTTL    time.Duration
	ICPErrorCacheTTL       time.Duration
	ICPBaseURL             string
	ICPUpstreamURL         string
	ICPCaptchaEnabled      bool
	ICPCaptchaRetries      int
	ICPSign                string
	ICPPageSize            int
	ICPBlocklist           []string
	RateLimitEnabled       bool
	RateLimitAnon          string
	TrustProxy             bool
	MetricsEnabled         bool
	Reporter               string
	ReporterWebhookURL     string
	ReporterTimeout        time.Duration
	PSLAutoUpdate          bool
	PSLURL                 string
	PSLUpdateTimeout       time.Duration
	ConfigPath             string
	ConfigCreated          bool
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
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadExistingWithError(configPath string) (Config, error) {
	cfg := Default()
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath, _ = configPathFromEnv(cfg.DataDir)
	}
	if configPath != "" {
		cfg.ConfigPath = configPath
		if err := applyFile(&cfg, configPath); err != nil {
			return cfg, err
		}
	}
	applyEnv(&cfg)
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = configPath
	}
	cfg.ConfigCreated = false
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

var defaultAIIgnoreSuffixes = []string{
	"com", "net", "org", "info", "biz", "name", "pro",
	"app", "dev", "page", "xyz", "top", "shop", "site", "online", "store", "cloud",
	"io", "co", "me", "tv", "cc",
	"us", "uk", "de", "fr", "nl", "eu", "jp", "kr", "cn", "tw", "hk", "au", "ca", "in",
	"ru", "br", "pl", "it", "es", "se", "ch", "no", "fi", "dk", "be", "at", "cz", "mx", "za",
	"co.uk", "org.uk", "me.uk",
	"com.cn", "net.cn", "org.cn", "ac.cn", "edu.cn", "gov.cn",
	"com.hk", "net.hk", "org.hk", "com.tw", "net.tw", "org.tw",
	"com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
	"com.br", "net.br", "com.mx", "co.nz", "org.nz", "com.sg", "com.my", "co.in", "net.in", "org.in", "co.za",
}

func DefaultAIIgnoreSuffixes() []string {
	return append([]string(nil), defaultAIIgnoreSuffixes...)
}

func Default() Config {
	return Config{
		Addr:                   ":8080",
		LookupTimeout:          15 * time.Second,
		ProviderTimeout:        10 * time.Second,
		DataDir:                "data",
		APIEnabled:             true,
		APIHealthEnabled:       true,
		APIVersionEnabled:      true,
		APICapabilitiesEnabled: true,
		APIMetricsEnabled:      true,
		APILookupEnabled:       true,
		APILookupAIEnabled:     true,
		APILookupEnrichEnabled: true,
		APIICPEnabled:          true,
		APIAdminEnabled:        true,
		APIAdminStatusEnabled:  true,
		APIAdminConfigEnabled:  true,
		AuthMode:               "none",
		RDAPEnabled:            true,
		WHOISEnabled:           true,
		WHOISFollowLimit:       1,
		LookupFastResponse:     true,
		EnrichEPP:              true,
		EnrichRegistrar:        true,
		EnrichDNS:              true,
		DNSTimeout:             3 * time.Second,
		DNSIPv4Resolvers:       parseList("1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,180.184.1.1,180.184.2.2"),
		DNSIPv6Resolvers:       parseList("2606:4700:4700::1111,2606:4700:4700::1001,2001:4860:4860::8888,2001:4860:4860::8844"),
		DNSDoHResolvers:        parseList("https://cloudflare-dns.com/dns-query,https://dns.google/resolve,https://doh.pub/dns-query,https://dns.alidns.com/dns-query"),
		DNSFilterFakeIP:        true,
		EnrichDNSViz:           true,
		AIProvider:             "openai-compatible",
		AITimeout:              8 * time.Second,
		AICacheTTL:             168 * time.Hour,
		AIMaxInputChars:        16000,
		AIMinConfidence:        0.68,
		AIMaxOutputTokens:      700,
		AIMaxAttempts:          3,
		AIIgnoreSuffixes:       DefaultAIIgnoreSuffixes(),
		ICPEnabled:             true,
		ICPTimeout:             8 * time.Second,
		ICPCacheTTL:            72 * time.Hour,
		ICPNegativeCacheTTL:    12 * time.Hour,
		ICPErrorCacheTTL:       10 * time.Minute,
		ICPBaseURL:             "https://hlwicpfwc.miit.gov.cn/icpproject_query/api",
		ICPCaptchaEnabled:      true,
		ICPCaptchaRetries:      3,
		ICPSign:                "eyJ0eXBlIjozLCJleHREYXRhIjp7InZhZnljb2RlX2ltYWdlX2tleSI6IjUyZWI1ZTcyODViNzRmNWJhM2YwYzBkNTg0YTg3NmVmIn0sImUiOjE3NTY5NzAyNDg4MjN9.Ngpkwn4T7sQoQF9pCk_sQQpH61wQUEKnK2sQ8hDIq-Q",
		ICPPageSize:            10,
		RateLimitAnon:          "60/min",
		MetricsEnabled:         true,
		Reporter:               "none",
		ReporterTimeout:        2 * time.Second,
		PSLURL:                 "https://publicsuffix.org/list/public_suffix_list.dat",
		PSLUpdateTimeout:       5 * time.Second,
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
		API:            c.APIEnabled,
		APIEndpoints:   c.APIEndpointMap(),
		APIIPAllowlist: len(cleanList(c.APIIPAllowlist)) > 0,
		RDAP:           c.RDAPEnabled,
		WHOIS:          c.WHOISEnabled,
		WHOISWeb:       c.WHOISWebEnabled,
		CustomServers:  c.AllowCustomServers,
		Auth:           c.AuthMode,
		RateLimit:      c.RateLimitEnabled,
		ICPAutoQuery:   c.ICPAutoQuery,
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

func (c Config) APIEndpointMap() map[string]bool {
	return map[string]bool{
		"health":       c.APIHealthEnabled,
		"version":      c.APIVersionEnabled,
		"capabilities": c.APICapabilitiesEnabled,
		"metrics":      c.APIMetricsEnabled,
		"lookup":       c.APILookupEnabled,
		"lookupAI":     c.APILookupAIEnabled,
		"lookupEnrich": c.APILookupEnrichEnabled,
		"icp":          c.APIICPEnabled,
		"admin":        c.APIAdminEnabled,
		"adminStatus":  c.APIAdminEnabled && c.APIAdminStatusEnabled,
		"adminConfig":  c.APIAdminEnabled && c.APIAdminConfigEnabled,
	}
}

func (c Config) Validate() error {
	var problems []string
	checkPositiveDuration := func(name string, value time.Duration) {
		if value <= 0 {
			problems = append(problems, fmt.Sprintf("%s must be greater than 0", name))
		}
	}
	checkPositiveDuration("lookup.timeout", c.LookupTimeout)
	checkPositiveDuration("lookup.provider_timeout", c.ProviderTimeout)
	checkPositiveDuration("dns.timeout", c.DNSTimeout)
	checkPositiveDuration("ai.timeout", c.AITimeout)
	checkPositiveDuration("icp.timeout", c.ICPTimeout)
	checkPositiveDuration("observability.timeout", c.ReporterTimeout)
	checkPositiveDuration("public_suffix.update_timeout", c.PSLUpdateTimeout)

	if strings.TrimSpace(c.Addr) == "" {
		problems = append(problems, "server.addr must not be empty")
	}
	if strings.TrimSpace(c.DataDir) == "" {
		problems = append(problems, "server.data_dir must not be empty")
	}
	switch strings.ToLower(strings.TrimSpace(c.AuthMode)) {
	case "", "none":
	case "password":
		if strings.TrimSpace(c.SitePassword) == "" {
			problems = append(problems, "auth.site_password is required when auth.mode = \"password\"")
		}
	case "token", "bearer":
		if len(cleanList(c.APITokens)) == 0 {
			problems = append(problems, "auth.api_tokens is required when auth.mode = \"token\"")
		}
	default:
		problems = append(problems, "auth.mode must be one of none, password, token, bearer")
	}
	if c.WHOISFollowLimit < 0 || c.WHOISFollowLimit > 5 {
		problems = append(problems, "lookup.whois_follow_limit must be between 0 and 5")
	}
	for _, entry := range cleanList(c.APIIPAllowlist) {
		if ip := net.ParseIP(entry); ip != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			problems = append(problems, "api.ip_allowlist entries must be IP addresses or CIDR ranges: "+entry)
		}
	}
	if c.AIMaxInputChars <= 0 {
		problems = append(problems, "ai.max_input_chars must be greater than 0")
	}
	if c.AIMinConfidence < 0 || c.AIMinConfidence > 1 {
		problems = append(problems, "ai.min_confidence must be between 0 and 1")
	}
	if c.AITemperature < 0 || c.AITemperature > 2 {
		problems = append(problems, "ai.temperature must be between 0 and 2")
	}
	if c.AIMaxOutputTokens <= 0 {
		problems = append(problems, "ai.max_output_tokens must be greater than 0")
	}
	if c.AIMaxAttempts < 1 || c.AIMaxAttempts > 3 {
		problems = append(problems, "ai.max_attempts must be between 1 and 3")
	}
	for _, suffix := range cleanList(c.AIIgnoreSuffixes) {
		if normalizeAIIgnoreSuffix(suffix) == "" {
			problems = append(problems, "ai.ignore_suffixes entries must be domain suffixes")
		}
	}
	for _, pattern := range cleanList(c.AIIgnoreRegex) {
		if _, err := regexp.Compile(pattern); err != nil {
			problems = append(problems, "ai.ignore_regex contains invalid regex "+strconv.Quote(pattern)+": "+err.Error())
		}
	}
	if c.AIEnabled {
		if strings.TrimSpace(c.AIBaseURL) == "" {
			problems = append(problems, "ai.base_url is required when ai.enabled = true")
		} else if err := validateHTTPURL(c.AIBaseURL); err != nil {
			problems = append(problems, "ai.base_url "+err.Error())
		}
		if strings.TrimSpace(c.AIModel) == "" {
			problems = append(problems, "ai.model is required when ai.enabled = true")
		}
	}
	if c.ICPEnabled {
		if strings.TrimSpace(c.ICPBaseURL) == "" && strings.TrimSpace(c.ICPUpstreamURL) == "" {
			problems = append(problems, "icp.base_url or icp.upstream_url is required when icp.enabled = true")
		}
		if strings.TrimSpace(c.ICPBaseURL) != "" {
			if err := validateHTTPURL(c.ICPBaseURL); err != nil {
				problems = append(problems, "icp.base_url "+err.Error())
			}
		}
		if strings.TrimSpace(c.ICPUpstreamURL) != "" {
			if err := validateHTTPURL(c.ICPUpstreamURL); err != nil {
				problems = append(problems, "icp.upstream_url "+err.Error())
			}
		}
		if c.ICPPageSize <= 0 {
			problems = append(problems, "icp.page_size must be greater than 0")
		}
		if c.ICPCaptchaRetries < 0 {
			problems = append(problems, "icp.captcha_retries must not be negative")
		}
	}
	if c.PSLAutoUpdate {
		if strings.TrimSpace(c.PSLURL) == "" {
			problems = append(problems, "public_suffix.url is required when public_suffix.auto_update = true")
		} else if err := validateHTTPURL(c.PSLURL); err != nil {
			problems = append(problems, "public_suffix.url "+err.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New("invalid config: " + strings.Join(problems, "; "))
	}
	return nil
}

func (c Config) AIIgnoreReasonForSuffix(suffix string) string {
	suffix = normalizeAIIgnoreSuffix(suffix)
	if suffix == "" {
		return ""
	}
	for _, entry := range cleanList(c.AIIgnoreSuffixes) {
		if normalizeAIIgnoreSuffix(entry) == suffix {
			return "ignored by ai.ignore_suffixes: ." + suffix
		}
	}
	for _, pattern := range cleanList(c.AIIgnoreRegex) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(suffix) {
			return "ignored by ai.ignore_regex: " + pattern
		}
	}
	return ""
}

func normalizeAIIgnoreSuffix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, ".")
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return ""
		}
	}
	return value
}

func validateHTTPURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("is invalid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("must use http or https")
	}
	if parsed.Host == "" {
		return errors.New("must include a host")
	}
	return nil
}

type fileConfig struct {
	Server        *serverConfig        `toml:"server"`
	API           *apiConfig           `toml:"api"`
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

type apiConfig struct {
	Enabled     *bool               `toml:"enabled"`
	IPAllowlist []string            `toml:"ip_allowlist"`
	Endpoints   *apiEndpointsConfig `toml:"endpoints"`
}

type apiEndpointsConfig struct {
	Health       *bool `toml:"health"`
	Version      *bool `toml:"version"`
	Capabilities *bool `toml:"capabilities"`
	Metrics      *bool `toml:"metrics"`
	Lookup       *bool `toml:"lookup"`
	LookupAI     *bool `toml:"lookup_ai"`
	LookupEnrich *bool `toml:"lookup_enrich"`
	ICP          *bool `toml:"icp"`
	Admin        *bool `toml:"admin"`
	AdminStatus  *bool `toml:"admin_status"`
	AdminConfig  *bool `toml:"admin_config"`
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
	FastResponse     *bool   `toml:"fast_response"`
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
	IgnoreSuffixes  []string `toml:"ignore_suffixes"`
	IgnoreRegex     []string `toml:"ignore_regex"`
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
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	var file fileConfig
	if err := unmarshalConfigBody(body, &file); err != nil {
		return fmt.Errorf("parse config file %s: %w", path, err)
	}
	return file.apply(cfg)
}

func unmarshalConfigBody(body []byte, file *fileConfig) error {
	if err := toml.Unmarshal(body, file); err == nil {
		return nil
	} else {
		tomlErr := err
		decoded, decodeErr := decodeBase64Config(body)
		if decodeErr != nil {
			return tomlErr
		}
		if err := toml.Unmarshal(decoded, file); err != nil {
			return fmt.Errorf("%v; base64 decoded content is not valid TOML: %w", tomlErr, err)
		}
		return nil
	}
}

func decodeBase64Config(body []byte) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, string(body))
	if cleaned == "" {
		return nil, errors.New("empty base64 config")
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(cleaned)
		if err == nil {
			return bytes.TrimPrefix(decoded, []byte{0xef, 0xbb, 0xbf}), nil
		}
	}
	return nil, errors.New("invalid base64 config")
}

func (f fileConfig) apply(cfg *Config) error {
	if f.Server != nil {
		setString(&cfg.Addr, f.Server.Addr)
		setString(&cfg.DataDir, f.Server.DataDir)
		setBool(&cfg.TrustProxy, f.Server.TrustProxy)
		setBool(&cfg.AllowCustomServers, f.Server.AllowCustomServers)
		setBool(&cfg.AllowPrivateServers, f.Server.AllowPrivateServers)
	}
	if f.API != nil {
		setBool(&cfg.APIEnabled, f.API.Enabled)
		setList(&cfg.APIIPAllowlist, f.API.IPAllowlist)
		if f.API.Endpoints != nil {
			setBool(&cfg.APIHealthEnabled, f.API.Endpoints.Health)
			setBool(&cfg.APIVersionEnabled, f.API.Endpoints.Version)
			setBool(&cfg.APICapabilitiesEnabled, f.API.Endpoints.Capabilities)
			setBool(&cfg.APIMetricsEnabled, f.API.Endpoints.Metrics)
			setBool(&cfg.APILookupEnabled, f.API.Endpoints.Lookup)
			setBool(&cfg.APILookupAIEnabled, f.API.Endpoints.LookupAI)
			setBool(&cfg.APILookupEnrichEnabled, f.API.Endpoints.LookupEnrich)
			setBool(&cfg.APIICPEnabled, f.API.Endpoints.ICP)
			setBool(&cfg.APIAdminEnabled, f.API.Endpoints.Admin)
			setBool(&cfg.APIAdminStatusEnabled, f.API.Endpoints.AdminStatus)
			setBool(&cfg.APIAdminConfigEnabled, f.API.Endpoints.AdminConfig)
		}
	}
	if f.Auth != nil {
		setString(&cfg.AuthMode, f.Auth.Mode)
		setString(&cfg.SitePassword, f.Auth.SitePassword)
		setList(&cfg.APITokens, f.Auth.APITokens)
	}
	if f.Lookup != nil {
		if err := setDuration(&cfg.LookupTimeout, f.Lookup.Timeout, "lookup.timeout"); err != nil {
			return err
		}
		if err := setDuration(&cfg.ProviderTimeout, f.Lookup.ProviderTimeout, "lookup.provider_timeout"); err != nil {
			return err
		}
		setBool(&cfg.RDAPEnabled, f.Lookup.RDAPEnabled)
		setBool(&cfg.WHOISEnabled, f.Lookup.WHOISEnabled)
		setBool(&cfg.WHOISWebEnabled, f.Lookup.WHOISWebEnabled)
		setInt(&cfg.WHOISFollowLimit, f.Lookup.WHOISFollowLimit)
		setBool(&cfg.LookupFastResponse, f.Lookup.FastResponse)
	}
	if f.DNS != nil {
		setBool(&cfg.EnrichDNS, f.DNS.Enabled)
		if err := setDuration(&cfg.DNSTimeout, f.DNS.Timeout, "dns.timeout"); err != nil {
			return err
		}
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
		if err := setDuration(&cfg.AITimeout, f.AI.Timeout, "ai.timeout"); err != nil {
			return err
		}
		if err := setCacheDuration(&cfg.AICacheTTL, f.AI.CacheTTL, "ai.cache_ttl"); err != nil {
			return err
		}
		setInt(&cfg.AIMaxInputChars, f.AI.MaxInputChars)
		setFloat(&cfg.AIMinConfidence, f.AI.MinConfidence)
		setFloat(&cfg.AITemperature, f.AI.Temperature)
		setInt(&cfg.AIMaxOutputTokens, f.AI.MaxOutputTokens)
		setInt(&cfg.AIMaxAttempts, f.AI.MaxAttempts)
		setList(&cfg.AIIgnoreSuffixes, f.AI.IgnoreSuffixes)
		setList(&cfg.AIIgnoreRegex, f.AI.IgnoreRegex)
		setString(&cfg.AIPrompt, f.AI.Prompt)
	}
	if f.ICP != nil {
		setBool(&cfg.ICPEnabled, f.ICP.Enabled)
		setBool(&cfg.ICPAutoQuery, f.ICP.AutoQuery)
		if err := setDuration(&cfg.ICPTimeout, f.ICP.Timeout, "icp.timeout"); err != nil {
			return err
		}
		if err := setCacheDuration(&cfg.ICPCacheTTL, f.ICP.CacheTTL, "icp.cache_ttl"); err != nil {
			return err
		}
		if err := setCacheDuration(&cfg.ICPNegativeCacheTTL, f.ICP.NegativeCacheTTL, "icp.negative_cache_ttl"); err != nil {
			return err
		}
		if err := setCacheDuration(&cfg.ICPErrorCacheTTL, f.ICP.ErrorCacheTTL, "icp.error_cache_ttl"); err != nil {
			return err
		}
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
		if err := setDuration(&cfg.ReporterTimeout, f.Observability.Timeout, "observability.timeout"); err != nil {
			return err
		}
	}
	if f.PSL != nil {
		setBool(&cfg.PSLAutoUpdate, f.PSL.AutoUpdate)
		setString(&cfg.PSLURL, f.PSL.URL)
		if err := setDuration(&cfg.PSLUpdateTimeout, f.PSL.UpdateTimeout, "public_suffix.update_timeout"); err != nil {
			return err
		}
	}
	return nil
}

func applyEnv(cfg *Config) {
	envStringInto(&cfg.Addr, "WHOICE_API_ADDR")
	envBoolInto(&cfg.APIEnabled, "WHOICE_API_ENABLED")
	envListInto(&cfg.APIIPAllowlist, "WHOICE_API_IP_ALLOWLIST")
	envBoolInto(&cfg.APIHealthEnabled, "WHOICE_API_HEALTH_ENABLED")
	envBoolInto(&cfg.APIVersionEnabled, "WHOICE_API_VERSION_ENABLED")
	envBoolInto(&cfg.APICapabilitiesEnabled, "WHOICE_API_CAPABILITIES_ENABLED")
	envBoolInto(&cfg.APIMetricsEnabled, "WHOICE_API_METRICS_ENABLED")
	envBoolInto(&cfg.APILookupEnabled, "WHOICE_API_LOOKUP_ENABLED")
	envBoolInto(&cfg.APILookupAIEnabled, "WHOICE_API_LOOKUP_AI_ENABLED")
	envBoolInto(&cfg.APILookupEnrichEnabled, "WHOICE_API_LOOKUP_ENRICH_ENABLED")
	envBoolInto(&cfg.APIICPEnabled, "WHOICE_API_ICP_ENABLED")
	envBoolInto(&cfg.APIAdminEnabled, "WHOICE_API_ADMIN_ENABLED")
	envBoolInto(&cfg.APIAdminStatusEnabled, "WHOICE_API_ADMIN_STATUS_ENABLED")
	envBoolInto(&cfg.APIAdminConfigEnabled, "WHOICE_API_ADMIN_CONFIG_ENABLED")
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
	envBoolInto(&cfg.LookupFastResponse, "WHOICE_LOOKUP_FAST_RESPONSE")
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
	envListInto(&cfg.AIIgnoreSuffixes, "WHOICE_AI_IGNORE_SUFFIXES")
	envListInto(&cfg.AIIgnoreRegex, "WHOICE_AI_IGNORE_REGEX")
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

func setDuration(target *time.Duration, value *string, name string) error {
	if value == nil {
		return nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(*value))
	if err != nil {
		return fmt.Errorf("%s must be a duration: %w", name, err)
	}
	*target = parsed
	return nil
}

func setCacheDuration(target *time.Duration, value *string, name string) error {
	if value == nil {
		return nil
	}
	parsed, err := parseCacheDurationStrict(*value, *target)
	if err != nil {
		return fmt.Errorf("%s must be a cache TTL: %w", name, err)
	}
	*target = parsed
	return nil
}

func parseCacheDuration(value string, fallback time.Duration) time.Duration {
	parsed, err := parseCacheDurationStrict(value, fallback)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseCacheDurationStrict(value string, fallback time.Duration) (time.Duration, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback, nil
	}
	switch value {
	case "0", "0s", "none", "off", "false", "disable", "disabled", "no-cache", "nocache":
		return 0, nil
	case "-1", "forever", "permanent", "infinite", "infinity", "inf", "never":
		return -1, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback, err
	}
	if parsed < 0 {
		return -1, nil
	}
	return parsed, nil
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
