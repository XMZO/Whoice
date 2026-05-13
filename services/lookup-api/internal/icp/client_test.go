package icp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
)

func TestClientQueriesMIITAndCachesResult(t *testing.T) {
	var queryHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"params": map[string]any{
					"bussiness": "token",
					"expire":    600000,
				},
			})
		case "/icpAbbreviateInfo/queryByCondition/":
			queryHits.Add(1)
			if r.Header.Get("token") != "token" {
				t.Fatalf("missing token header")
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["unitName"] != "example.cn" || payload["serviceType"].(float64) != 1 {
				t.Fatalf("payload: %#v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    200,
				"success": true,
				"params": map[string]any{
					"list": []map[string]any{
						{
							"domain":           "example.cn",
							"unitName":         "Example Co",
							"natureName":       "企业",
							"mainLicence":      "京ICP备00000000号",
							"serviceLicence":   "京ICP备00000000号-1",
							"serviceName":      "Example",
							"updateRecordTime": "2026-05-12",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(config.Config{
		ICPEnabled:          true,
		ICPTimeout:          time.Second,
		ICPCacheTTL:         time.Hour,
		ICPNegativeCacheTTL: time.Hour,
		ICPErrorCacheTTL:    time.Minute,
		ICPBaseURL:          server.URL,
		ICPSign:             "sign",
		ICPPageSize:         10,
		DataDir:             t.TempDir(),
	})

	first, err := client.Query(context.Background(), "example.cn")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusFound || len(first.Records) != 1 {
		t.Fatalf("result: %#v", first)
	}
	if first.Records[0].ServiceLicence != "京ICP备00000000号-1" {
		t.Fatalf("record: %#v", first.Records[0])
	}

	second, err := client.Query(context.Background(), "example.cn")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Cached {
		t.Fatal("expected cached result")
	}
	if queryHits.Load() != 1 {
		t.Fatalf("query hits: got %d want 1", queryHits.Load())
	}
}

func TestClientQueriesICPQueryCompatibleUpstream(t *testing.T) {
	var queryHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query/web" {
			http.NotFound(w, r)
			return
		}
		queryHits.Add(1)
		if got := r.URL.Query().Get("search"); got != "example.cn" {
			t.Fatalf("search: got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    200,
			"success": true,
			"params": map[string]any{
				"list": []map[string]any{
					{
						"domain":           "example.cn",
						"unitName":         "Example Co",
						"natureName":       "企业",
						"mainLicence":      "京ICP备00000000号",
						"serviceLicence":   "京ICP备00000000号-1",
						"serviceName":      "Example",
						"updateRecordTime": "2026-05-12",
					},
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(config.Config{
		ICPEnabled:          true,
		ICPTimeout:          time.Second,
		ICPCacheTTL:         time.Hour,
		ICPNegativeCacheTTL: time.Hour,
		ICPErrorCacheTTL:    time.Minute,
		ICPUpstreamURL:      server.URL,
		ICPPageSize:         10,
		DataDir:             t.TempDir(),
	})

	result, err := client.Query(context.Background(), "example.cn")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusFound || result.Source != "icp-query" || len(result.Records) != 1 {
		t.Fatalf("result: %#v", result)
	}
	if queryHits.Load() != 1 {
		t.Fatalf("query hits: got %d want 1", queryHits.Load())
	}
}

func TestClientBlocklistReturnsHiddenNotFound(t *testing.T) {
	client := NewClient(config.Config{
		ICPEnabled:   true,
		ICPBlocklist: []string{"*.secret.example"},
		ICPTimeout:   time.Second,
	})
	result, err := client.Query(context.Background(), "www.secret.example")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusNotFound {
		t.Fatalf("status: got %q", result.Status)
	}
	if strings.Contains(strings.ToLower(result.Message), "block") || strings.Contains(result.Message, "屏蔽") {
		t.Fatalf("block reason leaked: %q", result.Message)
	}
}

func TestTTLForResultSupportsDisabledAndPermanentCache(t *testing.T) {
	found := ttlForResult(config.Config{ICPCacheTTL: 0}, Result{Status: StatusFound}, nil)
	if found != 0 {
		t.Fatalf("disabled found ttl: got %s", found)
	}
	negative := ttlForResult(config.Config{ICPNegativeCacheTTL: -1}, Result{Status: StatusNotFound}, nil)
	if negative != foreverTTL {
		t.Fatalf("permanent negative ttl: got %s", negative)
	}
	failed := ttlForResult(config.Config{ICPErrorCacheTTL: -1}, Result{Status: StatusError}, context.Canceled)
	if failed != foreverTTL {
		t.Fatalf("permanent error ttl: got %s", failed)
	}
}

func TestParseMIITNotFound(t *testing.T) {
	result := parseMIITResult("example.cn", []byte(`{"code":200,"success":true,"params":{"list":[]}}`))
	if result.Status != StatusNotFound {
		t.Fatalf("status: got %q", result.Status)
	}
}
