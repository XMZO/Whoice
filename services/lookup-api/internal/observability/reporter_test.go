package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewReporterModes(t *testing.T) {
	if reporter, err := NewReporter("none", "", time.Second); err != nil || reporter != nil {
		t.Fatalf("none reporter: reporter=%#v err=%v", reporter, err)
	}
	if reporter, err := NewReporter("log", "", time.Second); err != nil || reporter == nil {
		t.Fatalf("log reporter: reporter=%#v err=%v", reporter, err)
	}
	if _, err := NewReporter("webhook", "", time.Second); err == nil {
		t.Fatal("expected webhook without URL to fail")
	}
	if reporter, err := NewReporter("log,webhook", "https://example.test/hook", time.Second); err != nil || reporter == nil {
		t.Fatalf("multi reporter: reporter=%#v err=%v", reporter, err)
	}
}

func TestWebhookReporterPostsLookupEvent(t *testing.T) {
	received := make(chan LookupEvent, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method: got %s want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type: %q", r.Header.Get("Content-Type"))
		}
		var event LookupEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Fatal(err)
		}
		received <- event
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	reporter := WebhookReporter{URL: server.URL, Timeout: time.Second}
	reporter.ReportLookup(context.Background(), LookupEvent{
		TraceID:         "trace-webhook",
		Query:           "example.com",
		NormalizedQuery: "example.com",
		Type:            "domain",
		Status:          "registered",
		OK:              true,
		ElapsedMs:       42,
		Providers:       []ProviderTraceView{{Source: "rdap", Status: "ok", ElapsedMs: 40}},
	})

	select {
	case event := <-received:
		if event.TraceID != "trace-webhook" || !event.OK || len(event.Providers) != 1 {
			t.Fatalf("unexpected event: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for webhook event")
	}
}
