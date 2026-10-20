package admin

import (
	"sync"
	"time"
)

const (
	maxFailuresPerClient = 5
	maxFailuresGlobal    = 50
	failureWindow        = 15 * time.Minute
)

// Limiter throttles failed logins per client and across all clients.
type Limiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	global   []time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{failures: map[string][]time.Time{}}
}

// Allowed reports whether client may attempt a login now, and if not, when it may retry.
func (l *Limiter) Allowed(client string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global = recent(l.global, now)
	list := recent(l.failures[client], now)
	l.failures[client] = list
	if len(list) >= maxFailuresPerClient {
		return false, list[0].Add(failureWindow).Sub(now)
	}
	if len(l.global) >= maxFailuresGlobal {
		return false, l.global[0].Add(failureWindow).Sub(now)
	}
	return true, 0
}

func (l *Limiter) Fail(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[client] = append(recent(l.failures[client], now), now)
	l.global = append(recent(l.global, now), now)
}

func (l *Limiter) Succeed(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, client)
}

func recent(list []time.Time, now time.Time) []time.Time {
	cut := 0
	for cut < len(list) && now.Sub(list[cut]) >= failureWindow {
		cut++
	}
	return list[cut:]
}
