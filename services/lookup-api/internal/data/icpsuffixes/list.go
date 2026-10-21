// Package icpsuffixes holds the top-level domains whose domains can be
// ICP-filed in mainland China, that is, the TLDs approved by MIIT.
package icpsuffixes

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/idna"
)

//go:embed snapshots/icp-suffixes.json
var snapshotFS embed.FS

type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type File struct {
	Version     int      `json:"version"`
	Description string   `json:"description,omitempty"`
	UpdatedAt   string   `json:"updatedAt"`
	Sources     []Source `json:"sources"`
	Suffixes    []string `json:"suffixes"`
}

// List matches a domain suffix against the approved TLDs. Entries are keyed
// by their ASCII (punycode) form so ".中国" and ".xn--fiqs8s" both match.
type List struct {
	file File
	keys map[string]string
}

func Parse(reader io.Reader) (*List, error) {
	var file File
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	if len(file.Suffixes) == 0 {
		return nil, fmt.Errorf("ICP suffix list is empty")
	}
	list := &List{file: file, keys: map[string]string{}}
	for _, suffix := range file.Suffixes {
		list.add(suffix)
	}
	return list, nil
}

// NewDefault reads data/icp-suffixes/icp-suffixes.json from dataDir when it
// is mounted and falls back to the embedded snapshot.
func NewDefault(dataDir string) *List {
	if dataDir != "" {
		if body, err := os.ReadFile(filepath.Join(dataDir, "icp-suffixes", "icp-suffixes.json")); err == nil {
			if list, err := Parse(strings.NewReader(string(body))); err == nil {
				return list
			}
		}
	}
	body, err := snapshotFS.ReadFile("snapshots/icp-suffixes.json")
	if err == nil {
		if list, err := Parse(strings.NewReader(string(body))); err == nil {
			return list
		}
	}
	// The embedded snapshot is checked by tests; an empty list only means no
	// domain is marked as fileable.
	return &List{keys: map[string]string{}}
}

// WithExtra returns a copy that also accepts the configured extra suffixes,
// for TLDs approved after the built-in list was taken.
func (l *List) WithExtra(extra []string) *List {
	out := &List{file: l.file, keys: make(map[string]string, len(l.keys)+len(extra))}
	for key, value := range l.keys {
		out.keys[key] = value
	}
	for _, suffix := range extra {
		out.add(suffix)
	}
	return out
}

func (l *List) add(suffix string) {
	display := strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
	if display == "" {
		return
	}
	key, err := idna.Lookup.ToASCII(display)
	if err != nil || key == "" {
		key = display
	}
	if unicode, err := idna.Lookup.ToUnicode(key); err == nil && unicode != "" {
		display = unicode
	}
	if _, ok := l.keys[key]; !ok {
		l.keys[key] = display
	}
}

// Match reports whether a domain under suffix (its public suffix, such as
// "com.cn") can be ICP-filed: the full suffix or its TLD must be listed. It
// returns the listed entry that decided it, in Unicode form.
func (l *List) Match(suffix string) (string, bool) {
	if l == nil {
		return "", false
	}
	suffix = strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
	if suffix == "" {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(suffix)
	if err != nil || ascii == "" {
		ascii = suffix
	}
	if display, ok := l.keys[ascii]; ok {
		return display, true
	}
	tld := ascii[strings.LastIndex(ascii, ".")+1:]
	if display, ok := l.keys[tld]; ok {
		return display, true
	}
	return "", false
}

// Info describes the built-in list for the admin panel; configured extras
// are a setting of their own.
type Info struct {
	UpdatedAt string   `json:"updatedAt"`
	Sources   []Source `json:"sources"`
	Suffixes  []string `json:"suffixes"`
}

func (l *List) Info() Info {
	info := Info{Sources: []Source{}, Suffixes: []string{}}
	if l == nil {
		return info
	}
	info.UpdatedAt = l.file.UpdatedAt
	info.Sources = append(info.Sources, l.file.Sources...)
	for _, suffix := range l.file.Suffixes {
		info.Suffixes = append(info.Suffixes, strings.ToLower(strings.Trim(strings.TrimSpace(suffix), ".")))
	}
	return info
}
