package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/admin"
	"github.com/xmzo/whoice/services/lookup-api/internal/config"
	"github.com/xmzo/whoice/services/lookup-api/internal/observability"
)

type adminFixture struct {
	server   *Server
	password string
	path     string
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "whoice.toml")
	if err := os.WriteFile(path, []byte(strings.Replace(config.DefaultTemplate(dir), `site_password = ""`, `site_password = "do-not-leak"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadExistingWithError(path)
	if err != nil {
		t.Fatal(err)
	}
	server := New(cfg, nil, nil, observability.NewStats())
	manager, password, err := admin.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	server.SetAdmin(manager)
	server.SetConfigReloader(func(at time.Time) error {
		next, err := config.LoadExistingWithError(path)
		if err != nil {
			return err
		}
		return server.ApplyRuntime(next, nil, nil, at)
	})
	return adminFixture{server: server, password: password, path: path}
}

func (f adminFixture) do(method, path, body string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, request)
	return response
}

func (f adminFixture) login(t *testing.T) *http.Cookie {
	t.Helper()
	response := f.do(http.MethodPost, "/api/admin/login", `{"password":"`+f.password+`"}`, map[string]string{adminCSRFHeader: "1"})
	if response.Code != http.StatusOK {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == admin.SessionCookie {
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie flags: %+v", cookie)
			}
			return cookie
		}
	}
	t.Fatal("login did not set a session cookie")
	return nil
}

var csrf = map[string]string{adminCSRFHeader: "1"}

func TestAdminEndpointsUnavailableWithoutManager(t *testing.T) {
	server := New(config.Default(), nil, nil, observability.NewStats())
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/config", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d want 503", response.Code)
	}
}

func TestAdminLoginFlow(t *testing.T) {
	f := newAdminFixture(t)
	if r := f.do(http.MethodGet, "/api/admin/config", "", nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("config without session: %d", r.Code)
	}
	if r := f.do(http.MethodPost, "/api/admin/login", `{"password":"`+f.password+`"}`, nil); r.Code != http.StatusForbidden {
		t.Fatalf("login without CSRF header: %d", r.Code)
	}
	if r := f.do(http.MethodPost, "/api/admin/login", `{"password":"wrong"}`, csrf); r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", r.Code)
	}
	cookie := f.login(t)
	session := f.do(http.MethodGet, "/api/admin/session", "", nil, cookie)
	if !strings.Contains(session.Body.String(), `"authenticated":true`) {
		t.Fatalf("session: %s", session.Body.String())
	}
	if r := f.do(http.MethodGet, "/api/admin/status", "", nil, cookie); r.Code != http.StatusOK {
		t.Fatalf("status: %d", r.Code)
	}
	if r := f.do(http.MethodGet, "/api/admin/status", "", map[string]string{adminPasswordHeader: f.password}); r.Code != http.StatusOK {
		t.Fatalf("status with password header: %d", r.Code)
	}
	logout := f.do(http.MethodPost, "/api/admin/logout", "", csrf, cookie)
	if logout.Code != http.StatusOK || !strings.Contains(logout.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout: %d %s", logout.Code, logout.Header().Get("Set-Cookie"))
	}
}

func TestAdminLoginIsThrottled(t *testing.T) {
	f := newAdminFixture(t)
	for i := 0; i < 5; i++ {
		f.do(http.MethodPost, "/api/admin/login", `{"password":"wrong"}`, csrf)
	}
	r := f.do(http.MethodPost, "/api/admin/login", `{"password":"`+f.password+`"}`, csrf)
	if r.Code != http.StatusTooManyRequests || r.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d", r.Code)
	}
}

func TestAdminConfigReadHidesSecrets(t *testing.T) {
	f := newAdminFixture(t)
	r := f.do(http.MethodGet, "/api/admin/config", "", nil, f.login(t))
	if r.Code != http.StatusOK {
		t.Fatalf("config: %d %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), "do-not-leak") {
		t.Fatal("site password leaked")
	}
	var payload struct {
		Settings config.FileConfig  `json:"settings"`
		Secrets  config.SecretState `json:"secrets"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Secrets.SitePassword || payload.Settings.Lookup == nil || *payload.Settings.Lookup.Timeout != "15s" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestAdminConfigUpdateWritesAndApplies(t *testing.T) {
	f := newAdminFixture(t)
	cookie := f.login(t)
	body := `{"settings":{"lookup":{"timeout":"9s","whois_follow_limit":2},"dns":{"ipv6_resolvers":[]},"rate_limit":{"enabled":true,"anon":"30/min"}}}`
	if r := f.do(http.MethodPatch, "/api/admin/config", body, nil, cookie); r.Code != http.StatusForbidden {
		t.Fatalf("patch without CSRF header: %d", r.Code)
	}
	r := f.do(http.MethodPatch, "/api/admin/config", body, csrf, cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", r.Code, r.Body.String())
	}
	saved, err := config.LoadFileOnly(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.LookupTimeout != 9*time.Second || saved.WHOISFollowLimit != 2 || len(saved.DNSIPv6Resolvers) != 0 || !saved.RateLimitEnabled || saved.SitePassword != "do-not-leak" {
		t.Fatalf("file not updated as expected: %+v", saved)
	}
	if _, err := os.Stat(f.path + ".bak"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if got := f.server.snapshot().cfg.LookupTimeout; got != 9*time.Second {
		t.Fatalf("runtime not reloaded: %v", got)
	}
}

func TestAdminConfigUpdateRejections(t *testing.T) {
	f := newAdminFixture(t)
	cookie := f.login(t)
	cases := map[string]struct {
		body string
		code string
	}{
		"startup only":  {`{"settings":{"server":{"addr":":9090"}}}`, "startup_only"},
		"lockout":       {`{"settings":{"api":{"endpoints":{"admin":false}}}}`, "admin_lockout"},
		"allowlist":     {`{"settings":{"api":{"ip_allowlist":["10.9.9.9"]}}}`, "admin_lockout"},
		"bad duration":  {`{"settings":{"lookup":{"timeout":"soon"}}}`, "invalid_config"},
		"invalid value": {`{"settings":{"lookup":{"whois_follow_limit":9}}}`, "invalid_config"},
		"unknown field": {`{"settings":{"lookup":{"nope":true}}}`, "invalid_request"},
		"empty":         {`{"settings":{}}`, "empty_patch"},
	}
	before, _ := os.ReadFile(f.path)
	for name, tc := range cases {
		r := f.do(http.MethodPatch, "/api/admin/config", tc.body, csrf, cookie)
		if r.Code < 400 || !strings.Contains(r.Body.String(), tc.code) {
			t.Errorf("%s: got %d %s, want %s", name, r.Code, r.Body.String(), tc.code)
		}
	}
	after, _ := os.ReadFile(f.path)
	if string(before) != string(after) {
		t.Fatal("rejected patches must not modify the file")
	}

	t.Setenv("WHOICE_LOOKUP_TIMEOUT", "20s")
	r := f.do(http.MethodPatch, "/api/admin/config", `{"settings":{"lookup":{"timeout":"9s"}}}`, csrf, cookie)
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "env_locked") {
		t.Fatalf("env locked: %d %s", r.Code, r.Body.String())
	}
}

func TestAdminPasswordChange(t *testing.T) {
	f := newAdminFixture(t)
	cookie := f.login(t)
	if r := f.do(http.MethodPost, "/api/admin/password", `{"current":"wrong","next":"new-password-1"}`, csrf, cookie); r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current: %d", r.Code)
	}
	r := f.do(http.MethodPost, "/api/admin/password", `{"current":"`+f.password+`","next":"new-password-1"}`, csrf, cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("change: %d %s", r.Code, r.Body.String())
	}
	if old := f.do(http.MethodGet, "/api/admin/status", "", nil, cookie); old.Code != http.StatusUnauthorized {
		t.Fatalf("old session should be revoked, got %d", old.Code)
	}
	f.password = "new-password-1"
	f.login(t)
}
