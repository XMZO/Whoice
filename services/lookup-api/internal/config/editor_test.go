package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultTemplateRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whoice.toml")
	if err := os.WriteFile(path, []byte(DefaultTemplate("data")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFileOnly(path)
	if err != nil {
		t.Fatalf("load default template: %v", err)
	}
	want := Default()
	want.ConfigPath = path
	want.AIPrompt = DefaultAIPrompt
	want.TrustProxy = true
	assertSameConfig(t, got, want)
}

func TestRenderFileRoundTripsEditedValues(t *testing.T) {
	cfg := Default()
	cfg.DataDir = "/data"
	cfg.AuthMode = "password"
	cfg.SitePassword = `pa"ss\word`
	cfg.APITokens = []string{"one", "two"}
	cfg.APIIPAllowlist = []string{"10.0.0.0/8"}
	cfg.LookupTimeout = 1500 * time.Millisecond
	cfg.WHOISFollowLimit = 3
	cfg.DNSDoHResolvers = []string{"https://dns.example/dns-query"}
	cfg.DNSIPv6Resolvers = []string{}
	cfg.AIEnabled = true
	cfg.AIBaseURL = "https://api.example.com/v1"
	cfg.AIModel = "model-x"
	cfg.AIAPIKey = "secret"
	cfg.AICacheTTL = -1
	cfg.AIMinConfidence = 0.5
	cfg.AIPrompt = "Line one\nLine 'two'\n"
	cfg.ICPCacheTTL = 0
	cfg.ICPBlocklist = []string{"*.example.com"}
	cfg.ICPSign = "custom-sign"
	cfg.RateLimitEnabled = true
	cfg.RateLimitAnon = "30/min"
	cfg.Reporter = "webhook"
	cfg.ReporterWebhookURL = "http://10.0.0.2/hook"

	path := filepath.Join(t.TempDir(), "whoice.toml")
	if err := WriteFile(path, cfg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadFileOnly(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.ConfigPath = path
	cfg.AIPrompt = strings.TrimSpace(cfg.AIPrompt)
	assertSameConfig(t, got, cfg)
}

func TestWriteFileKeepsBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whoice.toml")
	if err := os.WriteFile(path, []byte("# hand written\n[lookup]\ntimeout = \"9s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFileOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil || !strings.Contains(string(backup), "hand written") {
		t.Fatalf("backup missing or wrong: %q %v", backup, err)
	}
	reloaded, err := LoadFileOnly(path)
	if err != nil || reloaded.LookupTimeout != 9*time.Second {
		t.Fatalf("rewritten file lost lookup.timeout: %v %v", reloaded.LookupTimeout, err)
	}
}

func TestEnvLockedFields(t *testing.T) {
	t.Setenv("WHOICE_AI_MODEL", "env-model")
	locked := EnvLockedFields()
	if locked["ai.model"] != "WHOICE_AI_MODEL" {
		t.Fatalf("ai.model should be env-locked, got %v", locked)
	}
	if _, ok := locked["ai.base_url"]; ok {
		t.Fatalf("ai.base_url should not be locked")
	}
}

func TestSettingsViewOmitsSecrets(t *testing.T) {
	cfg := Default()
	cfg.SitePassword = "pw"
	cfg.APITokens = []string{"t"}
	cfg.AIAPIKey = "k"
	cfg.ReporterWebhookURL = "http://hook"
	view := SettingsView(cfg)
	if view.Auth.SitePassword != nil || view.Auth.APITokens != nil || view.AI.APIKey != nil || view.Observability.WebhookURL != nil {
		t.Fatalf("settings view leaked a secret: %+v %+v %+v", view.Auth, view.AI, view.Observability)
	}
	secrets := SecretsOf(cfg)
	if !secrets.SitePassword || secrets.APITokens != 1 || !secrets.AIAPIKey || !secrets.ObservabilityHook {
		t.Fatalf("unexpected secret state: %+v", secrets)
	}
}

func assertSameConfig(t *testing.T, got, want Config) {
	t.Helper()
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := 0; i < gv.NumField(); i++ {
		g, w := gv.Field(i).Interface(), wv.Field(i).Interface()
		if gs, ok := g.([]string); ok && len(gs) == 0 {
			if ws, ok := w.([]string); ok && len(ws) == 0 {
				continue
			}
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: got %#v, want %#v", gv.Type().Field(i).Name, gv.Field(i).Interface(), wv.Field(i).Interface())
		}
	}
}

func TestDNSFirstSuffixes(t *testing.T) {
	cfg := Default()
	if !cfg.DNSFirstSuffix("ka.uy") || !cfg.DNSFirstSuffix("google.com.uy") || !cfg.DNSFirstSuffix("google.es") || cfg.DNSFirstSuffix("uy") || cfg.DNSFirstSuffix("example.com") {
		t.Fatal("default list should cover .uy and .es names only")
	}
	cfg.DNSFirstSuffixes = []string{".COM.UY", "es"}
	if cfg.DNSFirstSuffix("ka.uy") || !cfg.DNSFirstSuffix("google.com.uy") || !cfg.DNSFirstSuffix("google.es") {
		t.Fatal("entries match by suffix, case-insensitively")
	}
	cfg.DNSFirstSuffixes = []string{"bad suffix"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid entries must fail validation")
	}
}
