package rdapbootstrap

import (
	"context"
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

type SnapshotResolver struct {
	files map[string]bootstrapFile
}

func NewSnapshotResolver() (*SnapshotResolver, error) {
	files := make(map[string]bootstrapFile, 4)
	for _, kind := range []string{"dns", "ipv4", "ipv6", "asn"} {
		body, err := snapshotFS.ReadFile("snapshots/" + kind + ".json")
		if err != nil {
			return nil, err
		}
		var file bootstrapFile
		if err := json.Unmarshal(body, &file); err != nil {
			return nil, fmt.Errorf("parse RDAP snapshot %s: %w", kind, err)
		}
		files[kind] = file
	}
	return &SnapshotResolver{files: files}, nil
}

func (r *SnapshotResolver) BaseURL(_ context.Context, q model.NormalizedQuery) (string, bool, error) {
	kind, key, err := bootstrapKindAndKey(q)
	if err != nil {
		return "", false, err
	}
	file, ok := r.files[kind]
	if !ok {
		return "", false, fmt.Errorf("missing RDAP snapshot %s", kind)
	}
	switch kind {
	case "dns":
		return matchDNS(file, key)
	case "ipv4", "ipv6":
		return matchIP(file, key)
	case "asn":
		return matchASN(file, q.ASN)
	default:
		return "", false, fmt.Errorf("unsupported RDAP bootstrap kind %q", kind)
	}
}

type FileResolver struct {
	files map[string]bootstrapFile
}

func NewFileResolver(dataDir string) (*FileResolver, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, fmt.Errorf("empty RDAP data directory")
	}

	files := make(map[string]bootstrapFile, 4)
	for _, kind := range []string{"dns", "ipv4", "ipv6", "asn"} {
		body, err := readRDAPBootstrapFile(dataDir, kind)
		if err != nil {
			continue
		}
		var file bootstrapFile
		if err := json.Unmarshal(body, &file); err != nil {
			return nil, fmt.Errorf("parse RDAP data file %s: %w", kind, err)
		}
		files[kind] = file
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no RDAP bootstrap files found in %s", dataDir)
	}
	return &FileResolver{files: files}, nil
}

func (r *FileResolver) BaseURL(_ context.Context, q model.NormalizedQuery) (string, bool, error) {
	kind, key, err := bootstrapKindAndKey(q)
	if err != nil {
		return "", false, err
	}
	file, ok := r.files[kind]
	if !ok {
		return "", false, fmt.Errorf("missing RDAP data file %s", kind)
	}
	switch kind {
	case "dns":
		return matchDNS(file, key)
	case "ipv4", "ipv6":
		return matchIP(file, key)
	case "asn":
		return matchASN(file, q.ASN)
	default:
		return "", false, fmt.Errorf("unsupported RDAP bootstrap kind %q", kind)
	}
}

func readRDAPBootstrapFile(dataDir, kind string) ([]byte, error) {
	candidates := []string{
		filepath.Join(dataDir, "rdap-bootstrap", kind+".json"),
		filepath.Join(dataDir, kind+".json"),
	}
	var lastErr error
	for _, candidate := range candidates {
		body, err := os.ReadFile(candidate)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type FallbackResolver struct {
	Primary  Resolver
	Fallback Resolver
}

func (r FallbackResolver) BaseURL(ctx context.Context, q model.NormalizedQuery) (string, bool, error) {
	if r.Primary != nil {
		base, ok, err := r.Primary.BaseURL(ctx, q)
		if err == nil && ok {
			return base, true, nil
		}
	}
	if r.Fallback == nil {
		return "", false, nil
	}
	return r.Fallback.BaseURL(ctx, q)
}

func NewDefaultResolver(dataDir string) Resolver {
	httpResolver := NewHTTPResolver()
	snapshotResolver, err := NewSnapshotResolver()
	if err != nil {
		if fileResolver, fileErr := NewFileResolver(dataDir); fileErr == nil {
			return FallbackResolver{Primary: fileResolver, Fallback: httpResolver}
		}
		return httpResolver
	}
	base := FallbackResolver{
		Primary:  snapshotResolver,
		Fallback: httpResolver,
	}
	if fileResolver, err := NewFileResolver(dataDir); err == nil {
		return FallbackResolver{Primary: fileResolver, Fallback: base}
	}
	return base
}
