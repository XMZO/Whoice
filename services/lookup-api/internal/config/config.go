package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/model"
)

type Config struct {
	Addr                string
	LookupTimeout       time.Duration
	ProviderTimeout     time.Duration
	DataDir             string
	AuthMode            string
	SitePassword        string
	APITokens           []string
	RDAPEnabled         bool
	WHOISEnabled        bool
	WHOISWebEnabled     bool
	WHOISFollowLimit    int
	AllowCustomServers  bool
	AllowPrivateServers bool
	EnrichEPP           bool
	EnrichBrands        bool
	EnrichRegistrar     bool
	EnrichDNS           bool
	DNSTimeout          time.Duration
	EnrichDNSViz        bool
	EnrichPricing       bool
	EnrichMoz           bool
	RateLimitEnabled    bool
	RateLimitAnon       string
	TrustProxy          bool
	MetricsEnabled      bool
	PSLAutoUpdate       bool
	PSLURL              string
	PSLUpdateTimeout    time.Duration
}

func Load() Config {
	return Config{
		Addr:                envString("WHOICE_API_ADDR", ":8080"),
		LookupTimeout:       envDuration("WHOICE_LOOKUP_TIMEOUT", 15*time.Second),
		ProviderTimeout:     envDuration("WHOICE_PROVIDER_TIMEOUT", 10*time.Second),
		DataDir:             envString("WHOICE_DATA_DIR", "/data"),
		AuthMode:            envString("WHOICE_AUTH_MODE", "none"),
		SitePassword:        envString("WHOICE_SITE_PASSWORD", ""),
		APITokens:           envList("WHOICE_API_TOKENS"),
		RDAPEnabled:         envBool("WHOICE_RDAP_ENABLED", true),
		WHOISEnabled:        envBool("WHOICE_WHOIS_ENABLED", true),
		WHOISWebEnabled:     envBool("WHOICE_WHOIS_WEB_ENABLED", false),
		WHOISFollowLimit:    envInt("WHOICE_WHOIS_FOLLOW_LIMIT", 1),
		AllowCustomServers:  envBool("WHOICE_ALLOW_CUSTOM_SERVERS", false),
		AllowPrivateServers: envBool("WHOICE_ALLOW_PRIVATE_SERVERS", false),
		EnrichEPP:           envBool("WHOICE_ENRICH_EPP", true),
		EnrichBrands:        envBool("WHOICE_ENRICH_BRANDS", false),
		EnrichRegistrar:     envBool("WHOICE_ENRICH_REGISTRAR", true),
		EnrichDNS:           envBool("WHOICE_ENRICH_DNS", true),
		DNSTimeout:          envDuration("WHOICE_DNS_TIMEOUT", 3*time.Second),
		EnrichDNSViz:        envBool("WHOICE_ENRICH_DNSVIZ", true),
		EnrichPricing:       envBool("WHOICE_ENRICH_PRICING", false),
		EnrichMoz:           envBool("WHOICE_ENRICH_MOZ", false),
		RateLimitEnabled:    envBool("WHOICE_RATE_LIMIT_ENABLED", false),
		RateLimitAnon:       envString("WHOICE_RATE_LIMIT_ANON", "60/min"),
		TrustProxy:          envBool("WHOICE_TRUST_PROXY", false),
		MetricsEnabled:      envBool("WHOICE_METRICS_ENABLED", true),
		PSLAutoUpdate:       envBool("WHOICE_PSL_AUTO_UPDATE", false),
		PSLURL:              envString("WHOICE_PSL_URL", "https://publicsuffix.org/list/public_suffix_list.dat"),
		PSLUpdateTimeout:    envDuration("WHOICE_PSL_UPDATE_TIMEOUT", 5*time.Second),
	}
}

func (c Config) Capabilities() model.Capabilities {
	return model.Capabilities{
		RDAP:          c.RDAPEnabled,
		WHOIS:         c.WHOISEnabled,
		WHOISWeb:      c.WHOISWebEnabled,
		CustomServers: c.AllowCustomServers,
		Auth:          c.AuthMode,
		RateLimit:     c.RateLimitEnabled,
		Enrichment: map[string]bool{
			"epp":       c.EnrichEPP,
			"brands":    c.EnrichBrands,
			"registrar": c.EnrichRegistrar,
			"dns":       c.EnrichDNS,
			"dnsviz":    c.EnrichDNSViz,
			"pricing":   c.EnrichPricing,
			"moz":       c.EnrichMoz,
		},
	}
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envList(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
