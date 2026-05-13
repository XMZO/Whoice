package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type cache struct {
	mu      sync.Mutex
	file    string
	entries map[string]cacheEntry
}

type cacheEntry struct {
	Analysis  Analysis  `json:"analysis"`
	CachedAt  time.Time `json:"cachedAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

func newCache(dataDir string) *cache {
	c := &cache{
		file:    filepath.Join(dataDir, "cache", "ai-registration.json"),
		entries: map[string]cacheEntry{},
	}
	c.load()
	return c
}

func (c *cache) get(key string) (Analysis, bool) {
	if c == nil || key == "" {
		return Analysis{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || cacheExpired(entry, time.Now()) {
		if ok {
			delete(c.entries, key)
		}
		return Analysis{}, false
	}
	return entry.Analysis, true
}

func (c *cache) set(key string, analysis Analysis, ttl time.Duration) {
	if c == nil || key == "" || ttl == 0 {
		return
	}
	now := time.Now()
	entry := cacheEntry{
		Analysis: analysis,
		CachedAt: now,
	}
	if ttl > 0 {
		entry.ExpiresAt = now.Add(ttl)
	}
	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
	c.save()
}

func (c *cache) load() {
	body, err := os.ReadFile(c.file)
	if err != nil {
		return
	}
	var payload map[string]cacheEntry
	if err := json.Unmarshal(body, &payload); err != nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range payload {
		if key == "" || cacheExpired(entry, now) {
			continue
		}
		c.entries[key] = entry
	}
}

func (c *cache) save() {
	c.mu.Lock()
	payload := make(map[string]cacheEntry, len(c.entries))
	now := time.Now()
	for key, entry := range c.entries {
		if cacheExpired(entry, now) {
			continue
		}
		payload[key] = entry
	}
	c.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(c.file), 0o755); err != nil {
		return
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	tmp := c.file + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.file)
}

func cacheExpired(entry cacheEntry, now time.Time) bool {
	return !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt)
}
