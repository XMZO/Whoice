package whoisservers

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

//go:embed snapshots/*.json
var snapshotFS embed.FS

type Server struct {
	Host          string `json:"host"`
	QueryTemplate string `json:"queryTemplate,omitempty"`
}

type Resolver struct {
	servers map[string]Server
}

func NewResolver(dataDir ...string) Resolver {
	servers := defaultServers()
	if snapshotServers, err := loadSnapshotServers(); err == nil {
		mergeServers(servers, snapshotServers)
	}
	if len(dataDir) > 0 {
		if fileServers, err := loadFileServers(dataDir[0]); err == nil {
			mergeServers(servers, fileServers)
		}
	}
	return Resolver{servers: servers}
}

func (r Resolver) Resolve(q model.NormalizedQuery, override string) (Server, string, error) {
	query := q.Query
	if q.Type == model.QueryASN {
		query = fmt.Sprintf("AS%d", q.ASN)
	}
	if override != "" {
		return Server{Host: override, QueryTemplate: "{query}"}, query, nil
	}
	if q.Type == model.QueryDomain {
		if server, ok := r.lookupDomain(q); ok {
			return server, applyTemplate(server.QueryTemplate, query), nil
		}
	}
	return Server{Host: "whois.iana.org", QueryTemplate: "{query}"}, query, nil
}

func (r Resolver) lookupDomain(q model.NormalizedQuery) (Server, bool) {
	candidates := suffixCandidates(q.Query, q.Suffix, q.RegisteredDomain)
	for _, candidate := range candidates {
		if server, ok := r.servers[candidate]; ok && server.Host != "" {
			return server, true
		}
	}
	return Server{}, false
}

func suffixCandidates(query, suffix, registeredDomain string) []string {
	seen := map[string]bool{}
	var candidates []string
	add := func(value string) {
		value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		candidates = append(candidates, value)
	}
	labels := strings.Split(strings.Trim(strings.ToLower(query), "."), ".")
	for i := 0; i < len(labels); i++ {
		add(strings.Join(labels[i:], "."))
	}
	add(registeredDomain)
	add(suffix)
	return candidates
}

func applyTemplate(template, query string) string {
	if template == "" {
		return query
	}
	template = strings.ReplaceAll(template, "%s", "{query}")
	template = strings.TrimRight(template, "\r\n")
	return strings.ReplaceAll(template, "{query}", query)
}

func loadSnapshotServers() (map[string]Server, error) {
	return loadServerFiles(func(name string) ([]byte, error) {
		return snapshotFS.ReadFile("snapshots/" + name)
	})
}

func loadFileServers(dataDir string) (map[string]Server, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, fmt.Errorf("empty WHOIS server data directory")
	}
	candidates := []string{
		filepath.Join(dataDir, "whois-servers"),
		dataDir,
	}
	for _, base := range candidates {
		servers, err := loadServerFiles(func(name string) ([]byte, error) {
			return os.ReadFile(filepath.Join(base, name))
		})
		if err == nil && len(servers) > 0 {
			return servers, nil
		}
	}
	return nil, fmt.Errorf("no WHOIS server data files found in %s", dataDir)
}

func loadServerFiles(read func(string) ([]byte, error)) (map[string]Server, error) {
	servers := map[string]Server{}
	iana, ianaErr := read("iana.json")
	if ianaErr == nil {
		parsed, err := parseServerMap(iana)
		if err != nil {
			return nil, fmt.Errorf("parse iana WHOIS server data: %w", err)
		}
		mergeServers(servers, parsed)
	}
	extra, extraErr := read("extra.json")
	if extraErr == nil {
		parsed, err := parseServerMap(extra)
		if err != nil {
			return nil, fmt.Errorf("parse extra WHOIS server data: %w", err)
		}
		mergeServers(servers, parsed)
	}
	if ianaErr != nil && extraErr != nil {
		return nil, ianaErr
	}
	return servers, nil
}

func parseServerMap(body []byte) (map[string]Server, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	servers := make(map[string]Server, len(raw))
	for suffix, value := range raw {
		suffix = strings.Trim(strings.ToLower(strings.TrimSpace(suffix)), ".")
		if suffix == "" {
			continue
		}
		server, ok, err := parseServerValue(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", suffix, err)
		}
		if !ok {
			continue
		}
		servers[suffix] = server
	}
	return servers, nil
}

func parseServerValue(value json.RawMessage) (Server, bool, error) {
	var host string
	if err := json.Unmarshal(value, &host); err == nil {
		host = strings.TrimSpace(host)
		if host == "" {
			return Server{}, false, nil
		}
		return Server{Host: host, QueryTemplate: "{query}"}, true, nil
	}
	var object struct {
		Host          string `json:"host"`
		Query         string `json:"query"`
		QueryTemplate string `json:"queryTemplate"`
	}
	if err := json.Unmarshal(value, &object); err != nil {
		return Server{}, false, err
	}
	host = strings.TrimSpace(object.Host)
	if host == "" {
		return Server{}, false, nil
	}
	template := strings.TrimSpace(object.QueryTemplate)
	if template == "" {
		template = strings.TrimSpace(object.Query)
	}
	if template == "" {
		template = "{query}"
	}
	return Server{Host: host, QueryTemplate: template}, true, nil
}

func mergeServers(target map[string]Server, incoming map[string]Server) {
	for suffix, server := range incoming {
		if strings.TrimSpace(server.Host) == "" {
			continue
		}
		if server.QueryTemplate == "" {
			server.QueryTemplate = "{query}"
		}
		key := strings.ToLower(suffix)
		if existing, ok := target[key]; ok && existing.QueryTemplate != "" && existing.QueryTemplate != "{query}" && server.QueryTemplate == "{query}" {
			server.QueryTemplate = existing.QueryTemplate
		}
		target[key] = server
	}
}

func defaultServers() map[string]Server {
	return map[string]Server{
		"ai":  {Host: "whois.nic.ai", QueryTemplate: "{query}"},
		"am":  {Host: "whois.amnic.net", QueryTemplate: "{query}"},
		"app": {Host: "whois.nic.google", QueryTemplate: "{query}"},
		"au":  {Host: "whois.auda.org.au", QueryTemplate: "{query}"},
		"be":  {Host: "whois.dns.be", QueryTemplate: "{query}"},
		"br":  {Host: "whois.registro.br", QueryTemplate: "{query}"},
		"cn":  {Host: "whois.cnnic.cn", QueryTemplate: "{query}"},
		"com": {Host: "whois.verisign-grs.com", QueryTemplate: "={query}"},
		"eu":  {Host: "whois.eu", QueryTemplate: "{query}"},
		"fr":  {Host: "whois.nic.fr", QueryTemplate: "{query}"},
		"it":  {Host: "whois.nic.it", QueryTemplate: "{query}"},
		"jp":  {Host: "whois.jprs.jp", QueryTemplate: "{query}/e"},
		"net": {Host: "whois.verisign-grs.com", QueryTemplate: "={query}"},
		"org": {Host: "whois.publicinterestregistry.org", QueryTemplate: "{query}"},
		"uk":  {Host: "whois.nic.uk", QueryTemplate: "{query}"},
	}
}
