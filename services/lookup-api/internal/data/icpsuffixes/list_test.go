package icpsuffixes

import "testing"

func TestEmbeddedListMatchesApprovedTLDs(t *testing.T) {
	list := NewDefault("")
	for suffix, want := range map[string]string{
		"cn":         "cn",
		"com.cn":     "cn",
		"gd.cn":      "cn",
		"中国":         "中国",
		"xn--fiqs8s": "中国",
		"com":        "com",
		"top":        "top",
		"cc":         "cc",
		"xn--55qx5d": "公司",
	} {
		got, ok := list.Match(suffix)
		if !ok || got != want {
			t.Fatalf("Match(%q) = %q, %v; want %q", suffix, got, ok, want)
		}
	}
	for _, suffix := range []string{"org", "io", "us.kg", "co.uk", "eu.org", ""} {
		if got, ok := list.Match(suffix); ok {
			t.Fatalf("Match(%q) = %q; want no match", suffix, got)
		}
	}
}

func TestExtraSuffixesExtendTheList(t *testing.T) {
	list := NewDefault("").WithExtra([]string{".IO", "com", " "})
	if got, ok := list.Match("io"); !ok || got != "io" {
		t.Fatalf("extra suffix not matched: %q %v", got, ok)
	}
	info := list.Info()
	for _, suffix := range info.Suffixes {
		if suffix == "io" {
			t.Fatal("extras must not appear in the built-in list")
		}
	}
	if len(info.Suffixes) < 100 || info.UpdatedAt == "" || len(info.Sources) == 0 {
		t.Fatalf("unexpected info: %d suffixes, updated %q, %d sources", len(info.Suffixes), info.UpdatedAt, len(info.Sources))
	}
}
