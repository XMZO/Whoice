package config

import (
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

[dns]
ipv4_resolvers = ["9.9.9.9"]
ipv6_resolvers = []
doh_resolvers = ["https://dns.example/dns-query"]
filter_fake_ip = false

[ai]
enabled = true
model = "from-file"
temperature = 0.2
cache_ttl = "none"
max_attempts = 2

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
	if cfg.DNSFilterFakeIP {
		t.Fatal("fake-ip filter should be disabled by file config")
	}
	if !cfg.AIEnabled || cfg.AIModel != "from-env" || cfg.AITemperature != 0.2 || cfg.AICacheTTL != 0 || cfg.AIMaxAttempts != 2 {
		t.Fatalf("AI config: %#v", cfg)
	}
	if !cfg.ICPAutoQuery {
		t.Fatal("ICP auto query should be enabled by file config")
	}
	assertContains(t, cfg.ICPBlocklist, "example.com")
	assertContains(t, cfg.ICPBlocklist, "*.internal.example")
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
