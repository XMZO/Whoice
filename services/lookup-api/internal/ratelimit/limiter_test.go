package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBlocksAfterLimit(t *testing.T) {
	limiter, err := New(true, "2/min")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if !limiter.Allow("ip", now).Allowed {
		t.Fatal("first request should pass")
	}
	if !limiter.Allow("ip", now).Allowed {
		t.Fatal("second request should pass")
	}
	if limiter.Allow("ip", now).Allowed {
		t.Fatal("third request should be blocked")
	}
}

func TestLimiterResetsWindow(t *testing.T) {
	limiter, err := New(true, "1/min")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if !limiter.Allow("ip", now).Allowed {
		t.Fatal("first request should pass")
	}
	if limiter.Allow("ip", now.Add(30*time.Second)).Allowed {
		t.Fatal("request inside window should be blocked")
	}
	if !limiter.Allow("ip", now.Add(61*time.Second)).Allowed {
		t.Fatal("request after reset should pass")
	}
}
