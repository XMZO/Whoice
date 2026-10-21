package fx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testService(t *testing.T, dir string, ttl time.Duration, handler http.HandlerFunc) (*Service, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	s := New(dir, ttl)
	s.client = server.Client()
	s.sources = []source{
		{name: "broken", url: server.URL + "/broken", parse: parseOpenER},
		{name: "backup", url: server.URL + "/backup", parse: parseCurrencyAPI},
	}
	return s, &calls
}

func ratesHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/broken" {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	_, _ = w.Write([]byte(`{"date":"2026-10-21","usd":{"cny":7.1,"eur":0.9,"vnd":25000,"jpy":150}}`))
}

func TestSnapshotFallsBackAndKeepsOnlyNeededCurrencies(t *testing.T) {
	s, _ := testService(t, t.TempDir(), time.Hour, ratesHandler)
	snap := s.Snapshot(context.Background(), []string{"eur", "VND", ""}, true)
	if snap == nil || snap.Source != "backup" || snap.UpdatedAt != "2026-10-21" || snap.CachedAt == "" {
		t.Fatalf("snapshot: %#v", snap)
	}
	if len(snap.Rates) != 4 || snap.Rates["USD"] != 1 || snap.Rates["CNY"] != 7.1 || snap.Rates["EUR"] != 0.9 || snap.Rates["VND"] != 25000 {
		t.Fatalf("rates: %#v", snap.Rates)
	}
}

func TestSnapshotUsesCacheAndPersists(t *testing.T) {
	dir := t.TempDir()
	s, calls := testService(t, dir, time.Hour, ratesHandler)
	s.Snapshot(context.Background(), nil, true)
	before := calls.Load()
	s.Snapshot(context.Background(), nil, true)
	if calls.Load() != before {
		t.Fatal("fresh rates must come from the cache")
	}
	reloaded, reloadedCalls := testService(t, dir, time.Hour, ratesHandler)
	if snap := reloaded.Snapshot(context.Background(), nil, false); snap == nil || snap.Rates["CNY"] != 7.1 || reloadedCalls.Load() != 0 {
		t.Fatalf("persisted rates not used: %#v", snap)
	}
}

func TestExpiredRatesRefreshDependingOnPath(t *testing.T) {
	s, calls := testService(t, t.TempDir(), time.Hour, ratesHandler)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	s.Snapshot(context.Background(), nil, true)
	clock = clock.Add(2 * time.Hour)

	// Fast path: stale rates now, refresh in the background.
	before := calls.Load()
	if snap := s.Snapshot(context.Background(), nil, false); snap == nil {
		t.Fatal("stale rates should still be returned")
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == before {
		t.Fatal("expired rates were not refreshed in the background")
	}

	// No rates at all and no fetching allowed: nothing to show yet.
	empty, _ := testService(t, t.TempDir(), time.Hour, ratesHandler)
	if snap := empty.Snapshot(context.Background(), nil, false); snap != nil {
		t.Fatalf("expected no rates before the first fetch, got %#v", snap)
	}
}
