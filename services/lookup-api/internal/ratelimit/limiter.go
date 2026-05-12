package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Decision struct {
	Allowed   bool
	Remaining int
	ResetAt   time.Time
}

type Limiter struct {
	enabled bool
	limit   int
	window  time.Duration
	mu      sync.Mutex
	buckets map[string]bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

func New(enabled bool, expression string) (Limiter, error) {
	limit, window, err := Parse(expression)
	if err != nil {
		return Limiter{}, err
	}
	return Limiter{
		enabled: enabled,
		limit:   limit,
		window:  window,
		buckets: map[string]bucket{},
	}, nil
}

func (l *Limiter) Allow(key string, now time.Time) Decision {
	if !l.enabled {
		return Decision{Allowed: true, Remaining: -1}
	}
	if key == "" {
		key = "anonymous"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	item := l.buckets[key]
	if item.resetAt.IsZero() || now.After(item.resetAt) {
		item = bucket{resetAt: now.Add(l.window)}
	}
	if item.count >= l.limit {
		l.buckets[key] = item
		return Decision{Allowed: false, Remaining: 0, ResetAt: item.resetAt}
	}
	item.count++
	l.buckets[key] = item
	return Decision{Allowed: true, Remaining: l.limit - item.count, ResetAt: item.resetAt}
}

func Parse(expression string) (int, time.Duration, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		expression = "60/min"
	}
	left, right, ok := strings.Cut(expression, "/")
	if !ok {
		return 0, 0, fmt.Errorf("invalid rate limit %q", expression)
	}
	limit, err := strconv.Atoi(strings.TrimSpace(left))
	if err != nil || limit <= 0 {
		return 0, 0, fmt.Errorf("invalid rate limit count %q", left)
	}
	switch strings.ToLower(strings.TrimSpace(right)) {
	case "s", "sec", "second":
		return limit, time.Second, nil
	case "m", "min", "minute":
		return limit, time.Minute, nil
	case "h", "hour":
		return limit, time.Hour, nil
	default:
		return 0, 0, fmt.Errorf("invalid rate limit window %q", right)
	}
}
