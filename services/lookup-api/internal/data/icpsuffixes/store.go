package icpsuffixes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// MIIT's 中国互联网域名体系 page (chinayu.jsp) loads the approved TLDs from
// this endpoint.
const (
	miitPage     = "https://domain.miit.gov.cn/chinayu.jsp"
	miitEndpoint = "https://domain.miit.gov.cn/yuming/getYMList"
	checkEvery   = time.Hour
)

// Store serves the list in use: MIIT's live list, cached in
// data/cache/icp-suffixes.json and refreshed when older than ttl, falling back
// to the built-in snapshot. A ttl of 0 keeps the built-in list; a negative
// ttl fetches once and keeps that answer.
type Store struct {
	path     string
	ttl      time.Duration
	extra    []string
	builtin  *List
	client   *http.Client
	endpoint string
	now      func() time.Time

	mu        sync.RWMutex
	list      *List
	fetchedAt time.Time
}

func NewStore(dataDir string, ttl time.Duration, extra []string) *Store {
	store := &Store{
		ttl:      ttl,
		extra:    append([]string{}, extra...),
		builtin:  NewDefault(dataDir),
		client:   &http.Client{Timeout: 15 * time.Second},
		endpoint: miitEndpoint,
		now:      time.Now,
	}
	if dataDir != "" {
		store.path = filepath.Join(dataDir, "cache", "icp-suffixes.json")
	}
	store.list = store.builtin.WithExtra(store.extra)
	if ttl != 0 {
		store.loadCache()
	}
	return store
}

// List returns the list to match against, extras included.
func (s *Store) List() *List {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list
}

// Info describes the list in use for the admin panel.
func (s *Store) Info() Info {
	if s == nil {
		return (*List)(nil).Info()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	info := s.list.Info()
	info.Origin = "builtin"
	if !s.fetchedAt.IsZero() {
		info.Origin = "miit"
		info.FetchedAt = s.fetchedAt.UTC().Format(time.RFC3339)
	}
	return info
}

// Start refreshes the list in the background whenever it is older than ttl,
// checking hourly, until ctx ends.
func (s *Store) Start(ctx context.Context) {
	if s == nil || s.ttl == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(checkEvery)
		defer ticker.Stop()
		for {
			if s.stale() {
				_ = s.Refresh(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *Store) stale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.fetchedAt.IsZero() {
		return true
	}
	return s.ttl > 0 && s.now().Sub(s.fetchedAt) > s.ttl
}

// Refresh fetches MIIT's list; on success it is cached and used at once.
// A failed or implausible answer leaves the current list in place.
func (s *Store) Refresh(ctx context.Context) error {
	suffixes, err := s.fetch(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	file := s.builtin.file
	file.Description = "MIIT's list of ICP-fileable TLDs, fetched from " + miitPage
	file.UpdatedAt = now.UTC().Format("2006-01-02")
	file.Sources = []Source{{Name: "工信部《中国互联网域名体系》", URL: miitPage}}
	file.Suffixes = suffixes
	file.FetchedAt = now.UTC().Format(time.RFC3339)
	list, err := parseFile(file)
	if err != nil {
		return err
	}
	s.writeCache(file)
	s.mu.Lock()
	s.list = list.WithExtra(s.extra)
	s.fetchedAt = now
	s.mu.Unlock()
	return nil
}

func (s *Store) loadCache() {
	if s.path == "" {
		return
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	list, err := Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}
	fetchedAt, err := time.Parse(time.RFC3339, list.file.FetchedAt)
	if err != nil {
		return
	}
	s.list = list.WithExtra(s.extra)
	s.fetchedAt = fetchedAt
}

func (s *Store) writeCache(file File) {
	if s.path == "" {
		return
	}
	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}

func (s *Store) fetch(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", miitPage)
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MIIT suffix list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseMIIT(body)
}

// ParseMIIT reads the getYMList answer: groups of {"DICT_NAME": ".COM"}.
// It rejects answers that do not look like the full list.
func ParseMIIT(body []byte) ([]string, error) {
	var groups map[string][]struct {
		Name string `json:"DICT_NAME"`
	}
	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, fmt.Errorf("MIIT suffix list: %w", err)
	}
	seen := map[string]bool{}
	var ascii, other []string
	for _, group := range []string{"cn", "china", "ch", "en"} {
		for _, item := range groups[group] {
			name := strings.ToLower(strings.TrimLeft(strings.TrimSpace(item.Name), ".．"))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			if isASCII(name) {
				ascii = append(ascii, name)
			} else {
				other = append(other, name)
			}
		}
	}
	for _, required := range []string{"cn", "中国", "com", "net"} {
		if !seen[required] {
			return nil, errors.New("MIIT suffix list: answer lacks ." + required)
		}
	}
	if len(seen) < 100 {
		return nil, fmt.Errorf("MIIT suffix list: only %d suffixes", len(seen))
	}
	sort.Strings(ascii)
	sort.Strings(other)
	return append(ascii, other...), nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}
