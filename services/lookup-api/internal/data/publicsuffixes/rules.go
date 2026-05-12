package publicsuffixes

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed snapshots/*.dat
var snapshotFS embed.FS

type Rules struct {
	exact         map[string]struct{}
	wildcard      map[string]struct{}
	exception     map[string]struct{}
	authoritative bool
}

func NewDefaultRules(dataDir string) Rules {
	rules := NewRules()
	if file, err := snapshotFS.Open("snapshots/public_suffix_list.dat"); err == nil {
		_ = rules.MergeFull(file)
		_ = file.Close()
	}
	if file, err := snapshotFS.Open("snapshots/extra.dat"); err == nil {
		_ = rules.Merge(file)
		_ = file.Close()
	}
	if dataDir != "" {
		for _, item := range []struct {
			path string
			full bool
		}{
			{path: filepath.Join(dataDir, "public-suffix", "public_suffix_list.dat"), full: true},
			{path: filepath.Join(dataDir, "public-suffix", "extra.dat")},
			{path: filepath.Join(dataDir, "public-suffixes", "public_suffix_list.dat"), full: true},
			{path: filepath.Join(dataDir, "public-suffixes", "extra.dat")},
		} {
			file, err := os.Open(item.path)
			if err != nil {
				continue
			}
			if item.full {
				_ = rules.MergeFull(file)
			} else {
				_ = rules.Merge(file)
			}
			_ = file.Close()
		}
	}
	return rules
}

func NewRules() Rules {
	return Rules{
		exact:     map[string]struct{}{},
		wildcard:  map[string]struct{}{},
		exception: map[string]struct{}{},
	}
}

func (r *Rules) Merge(reader io.Reader) error {
	return r.merge(reader, false)
}

func (r *Rules) MergeFull(reader io.Reader) error {
	return r.merge(reader, true)
}

func (r *Rules) merge(reader io.Reader, authoritative bool) error {
	if authoritative {
		r.authoritative = true
	}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		rule := normalizeRule(line)
		if rule == "" {
			continue
		}
		switch {
		case strings.HasPrefix(rule, "!"):
			value := strings.TrimPrefix(rule, "!")
			if value != "" {
				r.exception[value] = struct{}{}
			}
		case strings.HasPrefix(rule, "*."):
			value := strings.TrimPrefix(rule, "*.")
			if value != "" {
				r.wildcard[value] = struct{}{}
			}
		default:
			r.exact[rule] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read public suffix rules: %w", err)
	}
	return nil
}

func (r Rules) IsAuthoritative() bool {
	return r.authoritative
}

func (r Rules) PublicSuffix(domain string) (string, bool) {
	domain = normalizeRule(domain)
	if domain == "" {
		return "", false
	}
	labels := strings.Split(domain, ".")

	if suffix, ok := r.exceptionSuffix(labels); ok {
		return suffix, true
	}

	best := ""
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if _, ok := r.exact[candidate]; ok {
			best = longerSuffix(best, candidate)
		}
		if i+1 < len(labels) {
			base := strings.Join(labels[i+1:], ".")
			if _, ok := r.wildcard[base]; ok {
				best = longerSuffix(best, candidate)
			}
		}
	}
	return best, best != ""
}

func (r Rules) exceptionSuffix(labels []string) (string, bool) {
	best := ""
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if _, ok := r.exception[candidate]; !ok {
			continue
		}
		parts := strings.Split(candidate, ".")
		if len(parts) <= 1 {
			continue
		}
		best = longerSuffix(best, strings.Join(parts[1:], "."))
	}
	return best, best != ""
}

func EffectiveTLDPlusOne(domain, suffix string) string {
	domain = normalizeRule(domain)
	suffix = normalizeRule(suffix)
	if domain == "" || suffix == "" || domain == suffix || !strings.HasSuffix(domain, "."+suffix) {
		return ""
	}
	rest := strings.TrimSuffix(domain, "."+suffix)
	labels := strings.Split(rest, ".")
	return labels[len(labels)-1] + "." + suffix
}

func MoreSpecific(candidate, current string) bool {
	candidate = normalizeRule(candidate)
	current = normalizeRule(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	return labelCount(candidate) > labelCount(current)
}

func normalizeRule(value string) string {
	value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
	value = strings.TrimPrefix(value, ".")
	return value
}

func longerSuffix(current, candidate string) string {
	if MoreSpecific(candidate, current) {
		return candidate
	}
	return current
}

func labelCount(value string) int {
	if value == "" {
		return 0
	}
	return strings.Count(value, ".") + 1
}
