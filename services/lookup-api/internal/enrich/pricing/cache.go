package pricing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

// cacheEntry is one suffix in data/cache/pricing.json. Found is false for
// suffixes without pricing, so misses are not re-queried on every lookup.
type cacheEntry struct {
	Found    bool              `json:"found"`
	Info     model.PricingInfo `json:"info,omitempty"`
	CachedAt time.Time         `json:"cachedAt"`
}

// suffixCache keeps resolver answers per suffix and persists them as JSON.
// A negative ttl never expires; zero disables the cache.
type suffixCache struct {
	path    string
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	loaded  bool
	entries map[string]cacheEntry
}

func newSuffixCache(dataDir string, ttl time.Duration) *suffixCache {
	if ttl == 0 {
		return nil
	}
	path := ""
	if dataDir != "" {
		path = filepath.Join(dataDir, "cache", "pricing.json")
	}
	return &suffixCache{path: path, ttl: ttl, now: time.Now, entries: map[string]cacheEntry{}}
}

func (c *suffixCache) get(suffix string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	entry, ok := c.entries[suffix]
	if !ok || (c.ttl > 0 && c.now().Sub(entry.CachedAt) > c.ttl) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *suffixCache) put(suffix string, info model.PricingInfo, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	info.CachedAt = ""
	c.entries[suffix] = cacheEntry{Found: found, Info: info, CachedAt: c.now().UTC()}
	c.saveLocked()
}

func (c *suffixCache) loadLocked() {
	if c.loaded || c.path == "" {
		c.loaded = true
		return
	}
	c.loaded = true
	body, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var entries map[string]cacheEntry
	if json.Unmarshal(body, &entries) == nil && entries != nil {
		c.entries = entries
	}
}

// saveLocked writes the whole cache atomically; it is small (one entry per
// looked-up suffix) and failures only cost a re-fetch after restart.
func (c *suffixCache) saveLocked() {
	if c.path == "" {
		return
	}
	body, err := json.Marshal(c.entries)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}

// WithCache returns a resolver that answers repeated suffixes from a
// persistent per-suffix cache. Errors and fallback answers (an earlier
// source failed) are not cached.
func (r *Resolver) WithCache(dataDir string, ttl time.Duration) *Resolver {
	if r == nil {
		return nil
	}
	return &Resolver{sources: r.sources, cache: newSuffixCache(dataDir, ttl)}
}

func (r *Resolver) lookupCached(ctx context.Context, suffix string) (model.PricingInfo, bool, error) {
	if entry, ok := r.cache.get(suffix); ok {
		info := entry.Info
		info.CachedAt = entry.CachedAt.Format(time.RFC3339)
		return info, entry.Found, nil
	}
	info, found, degraded, err := r.lookupSourcesDetailed(ctx, suffix)
	if err != nil || degraded {
		return info, found, err
	}
	r.cache.put(suffix, info, found)
	return info, found, nil
}
