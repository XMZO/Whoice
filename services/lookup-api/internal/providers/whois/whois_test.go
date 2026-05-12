package whois

import (
	"testing"
)

func TestDecodeWHOISBodyKeepsUTF8(t *testing.T) {
	got := decodeWHOISBody([]byte("registrar: Example\n"))
	if got != "registrar: Example\n" {
		t.Fatalf("decoded: %q", got)
	}
}

func TestDecodeWHOISBodyHandlesWindows1252(t *testing.T) {
	got := decodeWHOISBody([]byte{0x52, 0xe9, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72})
	if got != "Régistrar" {
		t.Fatalf("decoded: %q", got)
	}
}
