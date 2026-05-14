package runtime

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/httpapi"
	"github.com/xmzo/whoice/services/lookup-api/internal/lookup"
	"github.com/xmzo/whoice/services/lookup-api/internal/model"
	"github.com/xmzo/whoice/services/lookup-api/internal/observability"
	"github.com/xmzo/whoice/services/lookup-api/internal/parsers"
	"github.com/xmzo/whoice/services/lookup-api/internal/providers"
)

func TestConfigWatcherRollsBackInvalidConfigAndAppliesNextValidConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "whoice.toml")
	writeConfig(t, configPath, `
[server]
addr = ":18080"
data_dir = "data"

[metrics]
enabled = true
`)
	t.Setenv("WHOICE_CONFIG", configPath)

	cfg, err := config.LoadWithError()
	if err != nil {
		t.Fatal(err)
	}
	service := lookup.NewService(cfg, []providers.Provider{reloadProvider{}}, parsers.NewRegistry(reloadParser{}))
	server, err := httpapi.NewStrict(cfg, service, nil, observability.NewStats())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartConfigWatcher(ctx, server, Builder{Addr: cfg.Addr, ConfigPath: cfg.ConfigPath}, 20*time.Millisecond)

	writeConfig(t, configPath, `
[server]
addr = ":18080"
data_dir = "data"

[lookup]
timeout = "fast"

[metrics]
enabled = false
`)
	waitFor(t, time.Second, func() bool {
		return server.ConfigStatus().Status == "error"
	})
	if !server.ConfigStatus().RolledBack {
		t.Fatalf("expected rolled back status: %#v", server.ConfigStatus())
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("old metrics config should remain active, got %d body=%s", metrics.Code, metrics.Body.String())
	}
	lookupResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(lookupResponse, httptest.NewRequest(http.MethodGet, "/api/lookup?query=example.com", nil))
	if !strings.Contains(lookupResponse.Body.String(), "Configuration reload failed") {
		t.Fatalf("lookup response should expose config warning: %s", lookupResponse.Body.String())
	}

	writeConfig(t, configPath, `
[server]
addr = ":18080"
data_dir = "data"

[metrics]
enabled = false
`)
	waitFor(t, time.Second, func() bool {
		return server.ConfigStatus().Status == "ok" && !server.ConfigStatus().RolledBack
	})
	metrics = httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if metrics.Code != http.StatusNotFound {
		t.Fatalf("valid reloaded metrics config should apply, got %d body=%s", metrics.Code, metrics.Body.String())
	}

	writeBase64Config(t, configPath, `
[server]
addr = ":18080"
data_dir = "data"

[metrics]
enabled = true
`)
	waitFor(t, time.Second, func() bool {
		metrics := httptest.NewRecorder()
		server.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
		return metrics.Code == http.StatusOK && server.ConfigStatus().Status == "ok" && !server.ConfigStatus().RolledBack
	})
	metrics = httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("base64 reloaded metrics config should apply, got %d body=%s", metrics.Code, metrics.Body.String())
	}
}

func writeConfig(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeBase64Config(t *testing.T, path string, body string) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(body) + "\n"))
	chunked := strings.Join(chunkString(encoded, 64), "\n")
	if err := os.WriteFile(path, []byte(chunked+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func chunkString(value string, width int) []string {
	if width <= 0 || len(value) <= width {
		return []string{value}
	}
	chunks := make([]string, 0, (len(value)+width-1)/width)
	for len(value) > width {
		chunks = append(chunks, value[:width])
		value = value[width:]
	}
	if value != "" {
		chunks = append(chunks, value)
	}
	return chunks
}

func waitFor(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

type reloadProvider struct{}

func (reloadProvider) Name() model.SourceName {
	return model.SourceWHOIS
}

func (reloadProvider) Supports(q model.NormalizedQuery) bool {
	return q.Type == model.QueryDomain
}

func (reloadProvider) Lookup(_ context.Context, q model.NormalizedQuery, _ model.LookupOptions) (*model.RawResponse, error) {
	return &model.RawResponse{
		Source: model.SourceWHOIS,
		Server: "whois.example.test",
		Query:  q.Query,
		Body: strings.Join([]string{
			"Domain Name: EXAMPLE.COM",
			"Registrar: Example Registrar",
			"Name Server: NS1.EXAMPLE.COM",
		}, "\n"),
		ContentType: "text/plain",
		StatusCode:  http.StatusOK,
	}, nil
}

type reloadParser struct{}

func (reloadParser) Name() string {
	return "reload-test"
}

func (reloadParser) Supports(raw model.RawResponse) bool {
	return raw.Source == model.SourceWHOIS
}

func (reloadParser) Priority() int {
	return 100
}

func (reloadParser) Parse(_ context.Context, raw model.RawResponse, q model.NormalizedQuery) (*model.PartialResult, error) {
	return &model.PartialResult{
		Source: model.SourceWHOIS,
		Status: model.StatusRegistered,
		Domain: model.DomainInfo{
			Name:             q.Query,
			RegisteredDomain: q.RegisteredDomain,
			Registered:       true,
		},
		Raw: model.RawData{WHOIS: raw.Body},
	}, nil
}
