package security

import (
	"context"
	"testing"
)

func TestServerPolicyBlocksPrivateRDAP(t *testing.T) {
	err := NewServerPolicy(false).AllowRDAP(context.Background(), "http://127.0.0.1:8080")
	if err == nil {
		t.Fatal("expected private RDAP target to be blocked")
	}
}

func TestServerPolicyBlocksWHOISScheme(t *testing.T) {
	err := NewServerPolicy(false).AllowWHOIS(context.Background(), "http://whois.example")
	if err == nil {
		t.Fatal("expected WHOIS scheme to be blocked")
	}
}

func TestServerPolicyAllowsPrivateWhenConfigured(t *testing.T) {
	err := NewServerPolicy(true).AllowWHOIS(context.Background(), "127.0.0.1:43")
	if err != nil {
		t.Fatalf("expected private target to be allowed in admin mode: %v", err)
	}
}
