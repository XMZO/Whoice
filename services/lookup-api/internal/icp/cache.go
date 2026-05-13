package icp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
)

func (c *Client) getCached(domain string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[domain]
	if !ok || cacheExpired(entry, time.Now()) {
		if ok {
			delete(c.cache, domain)
		}
		return Result{}, false
	}
	result := entry.Result
	result.Cached = true
	result.CachedAt = entry.CachedAt.UTC().Format(time.RFC3339)
	if !entry.ExpiresAt.IsZero() {
		result.ExpiresAt = entry.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return result, true
}

func (c *Client) store(domain string, result Result, ttl time.Duration) {
	if ttl == 0 {
		c.mu.Lock()
		_, existed := c.cache[domain]
		delete(c.cache, domain)
		c.mu.Unlock()
		if existed {
			c.saveCache()
		}
		return
	}
	now := time.Now()
	entry := cacheEntry{
		Result:   result,
		CachedAt: now,
	}
	if ttl > 0 {
		entry.ExpiresAt = now.Add(ttl)
	}
	entry.Result.Cached = false
	entry.Result.CachedAt = ""
	entry.Result.ExpiresAt = ""

	c.mu.Lock()
	c.cache[domain] = entry
	c.mu.Unlock()
	c.saveCache()
}

func (c *Client) loadCache() {
	if c.cacheFile == "" {
		return
	}
	body, err := os.ReadFile(c.cacheFile)
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
	for domain, entry := range payload {
		if domain == "" || cacheExpired(entry, now) {
			continue
		}
		c.cache[domain] = entry
	}
}

func (c *Client) saveCache() {
	if c.cacheFile == "" {
		return
	}
	c.mu.Lock()
	payload := make(map[string]cacheEntry, len(c.cache))
	now := time.Now()
	for domain, entry := range c.cache {
		if cacheExpired(entry, now) {
			continue
		}
		payload[domain] = entry
	}
	c.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(c.cacheFile), 0o755); err != nil {
		return
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	tmp := c.cacheFile + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.cacheFile)
}

func ttlForResult(cfg config.Config, result Result, err error) time.Duration {
	if result.Status == StatusFound {
		return normalizeCacheTTL(cfg.ICPCacheTTL)
	}
	if result.Status == StatusNotFound && err == nil {
		return normalizeCacheTTL(cfg.ICPNegativeCacheTTL)
	}
	return normalizeCacheTTL(cfg.ICPErrorCacheTTL)
}

func cachePath(dataDir string) string {
	return filepath.Join(dataDir, "cache", "icp.json")
}

const foreverTTL = time.Duration(-1)

func normalizeCacheTTL(ttl time.Duration) time.Duration {
	if ttl < 0 {
		return foreverTTL
	}
	return ttl
}

func cacheExpired(entry cacheEntry, now time.Time) bool {
	return !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt)
}

func (c *Client) isBlocked(domain string) bool {
	for _, pattern := range c.cfg.ICPBlocklist {
		pattern = normalizeDomain(pattern)
		if pattern == "" {
			continue
		}
		if pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return true
			}
			continue
		}
		if strings.HasPrefix(pattern, ".") {
			suffix := strings.TrimPrefix(pattern, ".")
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return true
			}
		}
	}
	return false
}
