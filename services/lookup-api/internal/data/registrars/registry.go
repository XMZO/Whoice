package registrars

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Registrar struct {
	Name          string
	IANAID        string
	Country       string
	PublicContact string
	URL           string
}

type Registry struct {
	byIANAID map[string]Registrar
	byName   map[string]Registrar
}

func NewRegistryFromReader(reader io.Reader) (*Registry, error) {
	csvReader := csv.NewReader(stripUTF8BOM(reader))
	csvReader.FieldsPerRecord = -1

	rows, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	registry := &Registry{
		byIANAID: map[string]Registrar{},
		byName:   map[string]Registrar{},
	}
	for index, row := range rows {
		if len(row) < 5 {
			continue
		}
		name := cleanCell(row[0])
		ianaID := cleanCell(row[1])
		if index == 0 && strings.EqualFold(name, "Registrar Name") {
			continue
		}
		if name == "" && ianaID == "" {
			continue
		}
		item := Registrar{
			Name:          name,
			IANAID:        ianaID,
			Country:       cleanCell(row[2]),
			PublicContact: cleanCell(row[3]),
			URL:           cleanCell(row[4]),
		}
		if item.IANAID != "" {
			registry.byIANAID[item.IANAID] = item
		}
		if key := normalizeName(item.Name); key != "" {
			registry.byName[key] = item
		}
	}
	return registry, nil
}

func stripUTF8BOM(reader io.Reader) io.Reader {
	body, err := io.ReadAll(reader)
	if err != nil {
		return reader
	}
	return bytes.NewReader(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
}

func NewFileRegistry(dataDir string) (*Registry, error) {
	for _, candidate := range fileCandidates(dataDir) {
		file, err := os.Open(candidate)
		if err != nil {
			continue
		}
		defer file.Close()
		registry, err := NewRegistryFromReader(file)
		if err != nil {
			return nil, fmt.Errorf("parse registrar data %s: %w", candidate, err)
		}
		return registry, nil
	}
	return nil, fmt.Errorf("no registrar data files found in %s", strings.TrimSpace(dataDir))
}

func (r *Registry) FindByIANAID(ianaID string) (Registrar, bool) {
	if r == nil {
		return Registrar{}, false
	}
	item, ok := r.byIANAID[strings.TrimSpace(ianaID)]
	return item, ok
}

func (r *Registry) FindByName(name string) (Registrar, bool) {
	if r == nil {
		return Registrar{}, false
	}
	item, ok := r.byName[normalizeName(name)]
	return item, ok
}

func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byIANAID)
}

func fileCandidates(dataDir string) []string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	return []string{
		filepath.Join(dataDir, "registrars", "icann-accredited-registrars.csv"),
		filepath.Join(dataDir, "icann-accredited-registrars.csv"),
		filepath.Join(dataDir, "icann-registrars.csv"),
	}
}

func cleanCell(value string) string {
	value = strings.TrimPrefix(value, "\ufeff")
	return strings.TrimSpace(value)
}

var registrarNameNoise = regexp.MustCompile(`(?i)\s+(?:incorporated|inc|llc|l\.l\.c|ltd|limited|corp|corporation|gmbh|sas|s\.a\.s|ag|bv|b\.v)\.?$`)

func normalizeName(value string) string {
	value = cleanCell(value)
	if value == "" {
		return ""
	}
	value = registrarNameNoise.ReplaceAllString(value, "")
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(
		"&", "and",
		",", "",
		".", "",
		"'", "",
		"`", "",
		"\"", "",
		"(", "",
		")", "",
		"-", "",
		"_", "",
		"/", "",
		" ", "",
	)
	return replacer.Replace(value)
}
