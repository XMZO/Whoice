package publicsuffixes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateFromRemote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`// ===BEGIN ICANN DOMAINS===
com
kg
edu.kg

// ===BEGIN PRIVATE DOMAINS===
de5.net
`))
	}))
	defer server.Close()

	dir := t.TempDir()
	if err := UpdateFromRemote(context.Background(), dir, server.URL, time.Second); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "public-suffix", "public_suffix_list.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "" {
		t.Fatal("expected downloaded PSL body")
	}
	if _, err := os.Stat(filepath.Join(dir, "public-suffix", "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestValidateListRejectsUnexpectedBody(t *testing.T) {
	if err := ValidateList([]byte("not a psl")); err == nil {
		t.Fatal("expected validation error")
	}
}
