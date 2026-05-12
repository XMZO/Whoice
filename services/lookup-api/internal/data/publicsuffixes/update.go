package publicsuffixes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultListURL = "https://publicsuffix.org/list/public_suffix_list.dat"

func UpdateFromRemote(ctx context.Context, dataDir, sourceURL string, timeout time.Duration) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return fmt.Errorf("data directory is required")
	}
	sourceURL = strings.TrimSpace(sourceURL)
	if sourceURL == "" {
		sourceURL = DefaultListURL
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Whoice/0.1 (+https://github.com/xmzo/whoice)")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("public suffix list HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024))
	if err != nil {
		return err
	}
	if err := ValidateList(body); err != nil {
		return err
	}

	dir := filepath.Join(dataDir, "public-suffix")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	target := filepath.Join(dir, "public_suffix_list.dat")
	if err := writeFileAtomic(target, body, 0o644); err != nil {
		return err
	}

	manifest := map[string]any{
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
		"sources": map[string]string{
			"publicSuffixList": sourceURL,
		},
		"sha256": map[string]string{
			"publicSuffixList": sha256Hex(body),
		},
	}
	manifestBody, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestBody = append(manifestBody, '\n')
	return writeFileAtomic(filepath.Join(dir, "manifest.json"), manifestBody, 0o644)
}

func ValidateList(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("public suffix list is empty")
	}
	text := string(body)
	required := []string{
		"BEGIN ICANN DOMAINS",
		"BEGIN PRIVATE DOMAINS",
		"\ncom\n",
	}
	for _, marker := range required {
		if !strings.Contains(text, marker) {
			return fmt.Errorf("public suffix list missing marker %q", strings.TrimSpace(marker))
		}
	}
	return nil
}

func writeFileAtomic(path string, body []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
