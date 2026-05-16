package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDNSResolverDefaults(t *testing.T) {
	disableConfigFile(t)
	unsetEnv(t, "WHOICE_DNS_IPV4_RESOLVERS")
	unsetEnv(t, "WHOICE_DNS_IPV6_RESOLVERS")

	cfg := Load()
	assertContains(t, cfg.DNSIPv4Resolvers, "1.1.1.1")
	assertContains(t, cfg.DNSIPv4Resolvers, "8.8.8.8")
	assertContains(t, cfg.DNSIPv4Resolvers, "180.184.1.1")
	assertContains(t, cfg.DNSIPv4Resolvers, "180.184.2.2")
	assertContains(t, cfg.DNSIPv6Resolvers, "2606:4700:4700::1111")
	assertContains(t, cfg.DNSIPv6Resolvers, "2001:4860:4860::8888")
	assertContains(t, cfg.DNSDoHResolvers, "https://cloudflare-dns.com/dns-query")
	assertContains(t, cfg.DNSDoHResolvers, "https://dns.google/resolve")
	assertContains(t, cfg.DNSDoHResolvers, "https://doh.pub/dns-query")
	assertContains(t, cfg.DNSDoHResolvers, "https://dns.alidns.com/dns-query")
	if !cfg.DNSFilterFakeIP {
		t.Fatal("fake-ip filtering should default to enabled")
	}
}

func TestLoadAPIDefaults(t *testing.T) {
	disableConfigFile(t)
	unsetEnv(t, "WHOICE_API_ENABLED")
	unsetEnv(t, "WHOICE_API_IP_ALLOWLIST")
	unsetEnv(t, "WHOICE_API_LOOKUP_ENABLED")
	unsetEnv(t, "WHOICE_API_LOOKUP_ENRICH_ENABLED")
	unsetEnv(t, "WHOICE_LOOKUP_FAST_RESPONSE")

	cfg := Load()
	if !cfg.APIEnabled || !cfg.APILookupEnabled || !cfg.APILookupEnrichEnabled {
		t.Fatalf("api defaults: %#v", cfg.APIEndpointMap())
	}
	if len(cfg.APIIPAllowlist) != 0 {
		t.Fatalf("api allowlist should default empty: %#v", cfg.APIIPAllowlist)
	}
	if !cfg.LookupFastResponse {
		t.Fatal("lookup fast_response should default to enabled")
	}
}

func TestLoadDNSResolverOverrides(t *testing.T) {
	disableConfigFile(t)
	t.Setenv("WHOICE_DNS_IPV4_RESOLVERS", "9.9.9.9,149.112.112.112")
	t.Setenv("WHOICE_DNS_IPV6_RESOLVERS", "none")
	t.Setenv("WHOICE_DNS_DOH_RESOLVERS", "none")
	t.Setenv("WHOICE_DNS_FILTER_FAKE_IP", "false")

	cfg := Load()
	if len(cfg.DNSIPv4Resolvers) != 2 || cfg.DNSIPv4Resolvers[0] != "9.9.9.9" || cfg.DNSIPv4Resolvers[1] != "149.112.112.112" {
		t.Fatalf("ipv4 resolvers: %#v", cfg.DNSIPv4Resolvers)
	}
	if len(cfg.DNSIPv6Resolvers) != 0 {
		t.Fatalf("ipv6 resolvers: %#v", cfg.DNSIPv6Resolvers)
	}
	if len(cfg.DNSDoHResolvers) != 0 {
		t.Fatalf("doh resolvers: %#v", cfg.DNSDoHResolvers)
	}
	if cfg.DNSFilterFakeIP {
		t.Fatal("fake-ip filtering should be disabled by override")
	}
}

func TestLoadICPDefaultsAndOverrides(t *testing.T) {
	disableConfigFile(t)
	unsetEnv(t, "WHOICE_ICP_ENABLED")
	unsetEnv(t, "WHOICE_ICP_AUTO_QUERY")
	unsetEnv(t, "WHOICE_ICP_CACHE_TTL")
	unsetEnv(t, "WHOICE_ICP_UPSTREAM_URL")
	unsetEnv(t, "WHOICE_ICP_CAPTCHA_ENABLED")
	unsetEnv(t, "WHOICE_ICP_CAPTCHA_RETRIES")

	cfg := Load()
	if !cfg.ICPEnabled {
		t.Fatal("ICP lookup should default to enabled")
	}
	if cfg.ICPAutoQuery {
		t.Fatal("ICP lookup should default to manual trigger")
	}
	if cfg.ICPCacheTTL.Hours() != 72 {
		t.Fatalf("cache ttl: got %s", cfg.ICPCacheTTL)
	}
	if cfg.ICPPageSize != 10 {
		t.Fatalf("page size: got %d", cfg.ICPPageSize)
	}
	if !cfg.ICPCaptchaEnabled {
		t.Fatal("ICP captcha mode should default to enabled")
	}

	t.Setenv("WHOICE_ICP_CACHE_TTL", "none")
	t.Setenv("WHOICE_ICP_NEGATIVE_CACHE_TTL", "forever")
	t.Setenv("WHOICE_ICP_ERROR_CACHE_TTL", "-1")
	cfg = Load()
	if cfg.ICPCacheTTL != 0 {
		t.Fatalf("disabled cache ttl: got %s", cfg.ICPCacheTTL)
	}
	if cfg.ICPNegativeCacheTTL != -1 {
		t.Fatalf("forever negative ttl: got %s", cfg.ICPNegativeCacheTTL)
	}
	if cfg.ICPErrorCacheTTL != -1 {
		t.Fatalf("forever error ttl: got %s", cfg.ICPErrorCacheTTL)
	}

	t.Setenv("WHOICE_ICP_ENABLED", "false")
	t.Setenv("WHOICE_ICP_AUTO_QUERY", "true")
	t.Setenv("WHOICE_ICP_CACHE_TTL", "24h")
	t.Setenv("WHOICE_ICP_NEGATIVE_CACHE_TTL", "12h")
	t.Setenv("WHOICE_ICP_ERROR_CACHE_TTL", "10m")
	t.Setenv("WHOICE_ICP_UPSTREAM_URL", "http://127.0.0.1:16181")
	t.Setenv("WHOICE_ICP_CAPTCHA_ENABLED", "false")
	t.Setenv("WHOICE_ICP_CAPTCHA_RETRIES", "5")
	t.Setenv("WHOICE_ICP_BLOCKLIST", "example.com, *.internal.example")
	cfg = Load()
	if cfg.ICPEnabled {
		t.Fatal("ICP lookup should be disabled by override")
	}
	if !cfg.ICPAutoQuery {
		t.Fatal("ICP auto query should be enabled by override")
	}
	if cfg.ICPCacheTTL.Hours() != 24 {
		t.Fatalf("cache ttl: got %s", cfg.ICPCacheTTL)
	}
	if cfg.ICPUpstreamURL != "http://127.0.0.1:16181" {
		t.Fatalf("upstream url: got %q", cfg.ICPUpstreamURL)
	}
	if cfg.ICPCaptchaEnabled {
		t.Fatal("ICP captcha mode should be disabled by override")
	}
	if cfg.ICPCaptchaRetries != 5 {
		t.Fatalf("captcha retries: got %d", cfg.ICPCaptchaRetries)
	}
	assertContains(t, cfg.ICPBlocklist, "example.com")
	assertContains(t, cfg.ICPBlocklist, "*.internal.example")
}

func TestLoadAIDefaultsAndOverrides(t *testing.T) {
	disableConfigFile(t)
	unsetEnv(t, "WHOICE_AI_ENABLED")
	unsetEnv(t, "WHOICE_AI_PROVIDER")
	unsetEnv(t, "WHOICE_AI_BASE_URL")
	unsetEnv(t, "WHOICE_AI_API_KEY")
	unsetEnv(t, "WHOICE_AI_MODEL")
	unsetEnv(t, "WHOICE_AI_TIMEOUT")
	unsetEnv(t, "WHOICE_AI_CACHE_TTL")
	unsetEnv(t, "WHOICE_AI_MAX_INPUT_CHARS")
	unsetEnv(t, "WHOICE_AI_MIN_CONFIDENCE")
	unsetEnv(t, "WHOICE_AI_TEMPERATURE")
	unsetEnv(t, "WHOICE_AI_MAX_OUTPUT_TOKENS")
	unsetEnv(t, "WHOICE_AI_MAX_ATTEMPTS")
	unsetEnv(t, "WHOICE_AI_IGNORE_SUFFIXES")
	unsetEnv(t, "WHOICE_AI_IGNORE_REGEX")
	unsetEnv(t, "WHOICE_AI_PROMPT")

	cfg := Load()
	if cfg.AIEnabled {
		t.Fatal("AI should default to disabled")
	}
	if cfg.AIProvider != "openai-compatible" {
		t.Fatalf("provider: %q", cfg.AIProvider)
	}
	if cfg.AICacheTTL.Hours() != 168 {
		t.Fatalf("cache ttl: %s", cfg.AICacheTTL)
	}
	if cfg.AIMaxInputChars != 16000 {
		t.Fatalf("max input chars: %d", cfg.AIMaxInputChars)
	}
	if cfg.AIMinConfidence != 0.68 {
		t.Fatalf("min confidence: %f", cfg.AIMinConfidence)
	}
	if cfg.AITemperature != 0 {
		t.Fatalf("temperature: %f", cfg.AITemperature)
	}
	if cfg.AIMaxOutputTokens != 700 {
		t.Fatalf("max output tokens: %d", cfg.AIMaxOutputTokens)
	}
	if cfg.AIMaxAttempts != 3 {
		t.Fatalf("max attempts: %d", cfg.AIMaxAttempts)
	}
	assertContains(t, cfg.AIIgnoreSuffixes, "com")
	assertContains(t, cfg.AIIgnoreSuffixes, "cn")
	assertContains(t, cfg.AIIgnoreSuffixes, "co.uk")
	if reason := cfg.AIIgnoreReasonForSuffix(".COM"); !strings.Contains(reason, "ai.ignore_suffixes") {
		t.Fatalf("ignore reason: got %q", reason)
	}

	t.Setenv("WHOICE_AI_ENABLED", "true")
	t.Setenv("WHOICE_AI_PROVIDER", "ollama")
	t.Setenv("WHOICE_AI_BASE_URL", "http://127.0.0.1:11434")
	t.Setenv("WHOICE_AI_API_KEY", "secret")
	t.Setenv("WHOICE_AI_MODEL", "qwen2.5:1.5b-instruct")
	t.Setenv("WHOICE_AI_TIMEOUT", "5s")
	t.Setenv("WHOICE_AI_CACHE_TTL", "none")
	t.Setenv("WHOICE_AI_MAX_INPUT_CHARS", "8000")
	t.Setenv("WHOICE_AI_MIN_CONFIDENCE", "0.75")
	t.Setenv("WHOICE_AI_TEMPERATURE", "0.1")
	t.Setenv("WHOICE_AI_MAX_OUTPUT_TOKENS", "500")
	t.Setenv("WHOICE_AI_MAX_ATTEMPTS", "2")
	t.Setenv("WHOICE_AI_IGNORE_SUFFIXES", "li, kz")
	t.Setenv("WHOICE_AI_IGNORE_REGEX", "^edu\\.")
	t.Setenv("WHOICE_AI_PROMPT", "Return JSON.")
	cfg = Load()
	if !cfg.AIEnabled {
		t.Fatal("AI should be enabled by override")
	}
	if cfg.AIProvider != "ollama" || cfg.AIBaseURL != "http://127.0.0.1:11434" || cfg.AIModel != "qwen2.5:1.5b-instruct" {
		t.Fatalf("AI config: %#v", cfg)
	}
	if cfg.AICacheTTL != 0 {
		t.Fatalf("disabled AI cache ttl: %s", cfg.AICacheTTL)
	}
	if cfg.AIMaxInputChars != 8000 || cfg.AIMinConfidence != 0.75 {
		t.Fatalf("AI thresholds: max=%d min=%f", cfg.AIMaxInputChars, cfg.AIMinConfidence)
	}
	if cfg.AITemperature != 0.1 || cfg.AIMaxOutputTokens != 500 || cfg.AIMaxAttempts != 2 {
		t.Fatalf("AI generation: temp=%f max=%d attempts=%d", cfg.AITemperature, cfg.AIMaxOutputTokens, cfg.AIMaxAttempts)
	}
	if reason := cfg.AIIgnoreReasonForSuffix("kz"); !strings.Contains(reason, "ai.ignore_suffixes") {
		t.Fatalf("suffix ignore reason: got %q", reason)
	}
	if reason := cfg.AIIgnoreReasonForSuffix("edu.cn"); !strings.Contains(reason, "ai.ignore_regex") {
		t.Fatalf("regex ignore reason: got %q", reason)
	}
}

func TestLoadCreatesDefaultConfigFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whoice.toml")
	t.Setenv("WHOICE_CONFIG", configPath)

	cfg, err := LoadWithError()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ConfigCreated {
		t.Fatal("expected config file to be created")
	}
	if cfg.ConfigPath != configPath {
		t.Fatalf("config path: got %q want %q", cfg.ConfigPath, configPath)
	}
	if cfg.DataDir != filepath.Dir(configPath) {
		t.Fatalf("data dir from generated config: got %q want %q", cfg.DataDir, filepath.Dir(configPath))
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	assertContainsString(t, string(body), "[dns]")
	assertContainsString(t, string(body), "doh_resolvers")
	assertContainsString(t, string(body), "epp: Explain domain status codes")
	assertContainsString(t, string(body), "pricing: Add new-registration/renewal/transfer prices by suffix")
	assertContainsString(t, string(body), "ignore_suffixes")
	assertContainsString(t, string(body), "ignore_regex")
	assertContainsString(t, string(body), "prompt = '''")
	assertContainsString(t, string(body), "You extract domain registration data")
}

func TestDefaultTemplateDocumentsOperationalSettings(t *testing.T) {
	body := DefaultTemplate("data")
	for _, want := range []string{
		"Duration values use Go duration syntax",
		"[api.endpoints]",
		"lookup_enrich is the background follow-up route",
		"allow_custom_servers",
		"fast_response = true",
		"Docker containers do not automatically inherit host IPv6",
		"DoH can query both A and AAAA records over IPv4 HTTPS",
		"Cache only structured AI analysis",
		"Skip AI for suffixes",
		"Setting prompt = \"\" is also valid",
		"Hidden ICP blocklist",
		"Fixed-window in-memory rate limit",
		"Public Suffix List source",
	} {
		assertContainsString(t, body, want)
	}
}

func TestLoadCreatesLocalDefaultConfigFile(t *testing.T) {
	unsetEnv(t, "WHOICE_CONFIG")
	unsetEnv(t, "WHOICE_CONFIG_AUTO_CREATE")
	unsetEnv(t, "WHOICE_DATA_DIR")
	t.Chdir(t.TempDir())

	cfg, err := LoadWithError()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ConfigCreated {
		t.Fatal("expected local default config to be created")
	}
	if cfg.ConfigPath != filepath.Join("data", "whoice.toml") {
		t.Fatalf("config path: got %q", cfg.ConfigPath)
	}
	if cfg.DataDir != "data" {
		t.Fatalf("data dir: got %q want data", cfg.DataDir)
	}
	if _, err := os.Stat(filepath.Join("data", "whoice.toml")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReadsTOMLAndEnvOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whoice.toml")
	if err := os.WriteFile(configPath, []byte(`
[server]
data_dir = "toml-data"
trust_proxy = true

[api]
enabled = true
ip_allowlist = ["203.0.113.0/24"]

[api.endpoints]
metrics = false
lookup_ai = false
lookup_enrich = true
admin_status = false

[dns]
ipv4_resolvers = ["9.9.9.9"]
ipv6_resolvers = []
doh_resolvers = ["https://dns.example/dns-query"]
filter_fake_ip = false

[ai]
enabled = true
base_url = "http://127.0.0.1:11434/v1"
model = "from-file"
temperature = 0.2
cache_ttl = "none"
max_attempts = 2
ignore_suffixes = []
ignore_regex = ["^museum$"]

[lookup]
fast_response = false

[icp]
auto_query = true
blocklist = ["example.com", "*.internal.example"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHOICE_CONFIG", configPath)
	t.Setenv("WHOICE_AI_MODEL", "from-env")
	t.Setenv("WHOICE_DNS_IPV6_RESOLVERS", "none")

	cfg, err := LoadWithError()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigCreated {
		t.Fatal("existing config should not be marked as created")
	}
	if cfg.DataDir != "toml-data" || !cfg.TrustProxy {
		t.Fatalf("server config not applied: %#v", cfg)
	}
	if len(cfg.DNSIPv4Resolvers) != 1 || cfg.DNSIPv4Resolvers[0] != "9.9.9.9" {
		t.Fatalf("ipv4 resolvers: %#v", cfg.DNSIPv4Resolvers)
	}
	if len(cfg.DNSIPv6Resolvers) != 0 {
		t.Fatalf("ipv6 env override should disable list: %#v", cfg.DNSIPv6Resolvers)
	}
	if !cfg.APIEnabled || cfg.APIMetricsEnabled || cfg.APILookupAIEnabled || !cfg.APILookupEnrichEnabled || cfg.APIAdminStatusEnabled {
		t.Fatalf("api endpoint config not applied: %#v", cfg.APIEndpointMap())
	}
	assertContains(t, cfg.APIIPAllowlist, "203.0.113.0/24")
	if cfg.LookupFastResponse {
		t.Fatal("lookup fast_response should be disabled by file config")
	}
	if cfg.DNSFilterFakeIP {
		t.Fatal("fake-ip filter should be disabled by file config")
	}
	if !cfg.AIEnabled || cfg.AIModel != "from-env" || cfg.AITemperature != 0.2 || cfg.AICacheTTL != 0 || cfg.AIMaxAttempts != 2 {
		t.Fatalf("AI config: %#v", cfg)
	}
	if len(cfg.AIIgnoreSuffixes) != 0 {
		t.Fatalf("empty TOML ignore_suffixes should disable suffix ignores: %#v", cfg.AIIgnoreSuffixes)
	}
	if reason := cfg.AIIgnoreReasonForSuffix("museum"); !strings.Contains(reason, "ai.ignore_regex") {
		t.Fatalf("regex ignore reason: got %q", reason)
	}
	if !cfg.ICPAutoQuery {
		t.Fatal("ICP auto query should be enabled by file config")
	}
	assertContains(t, cfg.ICPBlocklist, "example.com")
	assertContains(t, cfg.ICPBlocklist, "*.internal.example")
}

func TestLoadReadsBase64EncodedTOML(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whoice.toml")
	plain := `
[server]
data_dir = "encoded-data"

[dns]
ipv4_resolvers = ["9.9.9.9"]
ipv6_resolvers = []

[ai]
enabled = true
base_url = "http://127.0.0.1:11434/v1"
model = "encoded-model"
`
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	if err := os.WriteFile(configPath, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHOICE_CONFIG", configPath)

	cfg, err := LoadWithError()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "encoded-data" {
		t.Fatalf("data dir: got %q", cfg.DataDir)
	}
	if len(cfg.DNSIPv4Resolvers) != 1 || cfg.DNSIPv4Resolvers[0] != "9.9.9.9" {
		t.Fatalf("ipv4 resolvers: %#v", cfg.DNSIPv4Resolvers)
	}
	if len(cfg.DNSIPv6Resolvers) != 0 {
		t.Fatalf("ipv6 resolvers: %#v", cfg.DNSIPv6Resolvers)
	}
	if !cfg.AIEnabled || cfg.AIModel != "encoded-model" {
		t.Fatalf("AI config: %#v", cfg)
	}
}

func TestLoadRejectsInvalidFileConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whoice.toml")
	if err := os.WriteFile(configPath, []byte(`
[lookup]
timeout = "fast"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHOICE_CONFIG", configPath)

	_, err := LoadWithError()
	if err == nil {
		t.Fatal("expected invalid duration to fail")
	}
	if !strings.Contains(err.Error(), "lookup.timeout") {
		t.Fatalf("error should name invalid setting: %v", err)
	}
}

func TestLoadRejectsInvalidAIIgnoreRegex(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whoice.toml")
	if err := os.WriteFile(configPath, []byte(`
[ai]
ignore_regex = ["["]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHOICE_CONFIG", configPath)

	_, err := LoadWithError()
	if err == nil {
		t.Fatal("expected invalid AI ignore regex to fail")
	}
	if !strings.Contains(err.Error(), "ai.ignore_regex") {
		t.Fatalf("error should name invalid regex setting: %v", err)
	}
}

func TestLoadExistingDoesNotCreateMissingConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "missing.toml")
	t.Setenv("WHOICE_CONFIG", configPath)

	_, err := LoadExistingWithError(configPath)
	if err == nil {
		t.Fatal("expected missing runtime config reload to fail")
	}
	if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
		t.Fatalf("reload must not create missing config file, stat err=%v", statErr)
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%q missing from %#v", want, values)
}

func assertContainsString(t *testing.T, value, want string) {
	t.Helper()
	if !strings.Contains(value, want) {
		t.Fatalf("%q missing from %q", want, value)
	}
}

func disableConfigFile(t *testing.T) {
	t.Helper()
	t.Setenv("WHOICE_CONFIG_AUTO_CREATE", "false")
	unsetEnv(t, "WHOICE_CONFIG")
	unsetEnv(t, "WHOICE_DATA_DIR")
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	original, ok := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, original)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}
