package icpsuffixes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// miitAnswer builds a getYMList-shaped answer from the embedded list plus
// extra English entries.
func miitAnswer(t *testing.T, extra ...string) []byte {
	t.Helper()
	type item struct {
		Name string `json:"DICT_NAME"`
	}
	groups := map[string][]item{"cn": {{".CN"}}, "china": {{".中国"}}}
	for _, suffix := range append(NewDefault("").Info().Suffixes, extra...) {
		switch {
		case suffix == "cn" || suffix == "中国":
		case isASCII(suffix):
			groups["en"] = append(groups["en"], item{"." + strings.ToUpper(suffix)})
		default:
			groups["ch"] = append(groups["ch"], item{"." + suffix})
		}
	}
	body, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestStoreRefreshesFromMIITAndKeepsTheCache(t *testing.T) {
	answer := miitAnswer(t, "newtld")
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			t.Errorf("unexpected request %s %v", r.Method, r.Header)
		}
		_, _ = w.Write(answer)
	}))
	defer server.Close()

	dir := t.TempDir()
	store := NewStore(dir, 168*time.Hour, []string{"io"})
	store.endpoint = server.URL
	if _, ok := store.List().Match("newtld"); ok {
		t.Fatal("the built-in list must not know newtld yet")
	}
	if info := store.Info(); info.Origin != "builtin" {
		t.Fatalf("expected the built-in list before a fetch, got %q", info.Origin)
	}
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"newtld", "com", "中国", "io"} {
		if _, ok := store.List().Match(suffix); !ok {
			t.Fatalf("expected %s to match after the refresh", suffix)
		}
	}
	if info := store.Info(); info.Origin != "miit" || info.FetchedAt == "" {
		t.Fatalf("expected a fetched list, got %+v", info)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache", "icp-suffixes.json")); err != nil {
		t.Fatalf("expected a cache file: %v", err)
	}

	// A restart reads the cache; a failed refresh keeps it.
	restarted := NewStore(dir, 168*time.Hour, nil)
	restarted.endpoint = server.URL
	fail = true
	if err := restarted.Refresh(context.Background()); err == nil {
		t.Fatal("expected the refresh to fail")
	}
	if _, ok := restarted.List().Match("newtld"); !ok || restarted.Info().Origin != "miit" {
		t.Fatal("expected the cached list to survive a failed refresh")
	}

	// ttl 0 keeps the built-in list even with a cache on disk.
	if _, ok := NewStore(dir, 0, nil).List().Match("newtld"); ok {
		t.Fatal("ttl 0 must use the built-in list")
	}
}

func TestParseMIITRejectsPartialAnswers(t *testing.T) {
	if _, err := ParseMIIT([]byte(`{"en":[{"DICT_NAME":".COM"}],"cn":[{"DICT_NAME":".CN"}]}`)); err == nil {
		t.Fatal("expected a partial answer to be rejected")
	}
	if _, err := ParseMIIT([]byte(`<html>`)); err == nil {
		t.Fatal("expected a non-JSON answer to be rejected")
	}
}
