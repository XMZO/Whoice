package merger

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

var unicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})(?:\\u([0-9a-fA-F]{4}))?`)

// decodeUnicodeEscapes turns literal JSON-style escapes that some registries
// print in WHOIS text ("İzmir") into the characters they stand for.
// Only well-formed \uXXXX sequences that decode to printable characters are
// replaced; anything else is left as written.
func decodeUnicodeEscapes(value string) string {
	if !strings.Contains(value, `\u`) {
		return value
	}
	return unicodeEscape.ReplaceAllStringFunc(value, func(match string) string {
		parts := unicodeEscape.FindStringSubmatch(match)
		first, _ := strconv.ParseUint(parts[1], 16, 16)
		r := rune(first)
		rest := ""
		if parts[2] != "" {
			second, _ := strconv.ParseUint(parts[2], 16, 16)
			if utf16.IsSurrogate(r) {
				r = utf16.DecodeRune(r, rune(second))
			} else {
				rest = decodeUnicodeEscapes(`\u` + parts[2])
			}
		}
		if r == unicode.ReplacementChar || utf16.IsSurrogate(r) || !unicode.IsPrint(r) {
			return match
		}
		return string(r) + rest
	})
}

// privacyPlaceholders are values registries put in place of withheld
// contact data. Compared case-insensitively after trimming brackets and
// trailing punctuation.
var privacyPlaceholders = map[string]bool{
	"redacted": true, "redacted for privacy": true, "redacted for gdpr": true,
	"redacted for privacy purposes": true, "redacted | eu data subject": true,
	"not disclosed": true, "non-public data": true, "data protected": true,
	"data protected, not disclosed": true, "gdpr masked": true, "gdpr redacted": true,
	"statutory masking enabled": true, "withheld for privacy purposes": true,
	"hidden upon user request": true, "privacy protected": true,
	"not available": true, "n/a": true, "-": true,
}

// cleanContactValue decodes escapes and drops privacy placeholders, including
// placeholders joined from several lines ("REDACTED REDACTED").
func cleanContactValue(value string) string {
	value = strings.TrimSpace(decodeUnicodeEscapes(value))
	if value == "" {
		return ""
	}
	normalized := strings.ToLower(strings.Trim(value, "<>[]() .,;:!"))
	if privacyPlaceholders[normalized] {
		return ""
	}
	words := strings.FieldsFunc(normalized, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	allRedacted := len(words) > 0
	for _, word := range words {
		if word != "redacted" {
			allRedacted = false
			break
		}
	}
	if allRedacted {
		return ""
	}
	return value
}
