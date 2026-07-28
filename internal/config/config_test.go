package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoad(t *testing.T) {
	got, err := Load("testdata/tailgate.hujson")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := &Config{
		Node: Node{Hostname: "tailgate", StateDir: "/var/lib/tailgate", Port: 443},
		OIDC: OIDC{Issuer: "https://idp.tail-scale.ts.net"},
		Upstreams: []Upstream{
			{Name: "github", Transport: "http", URL: "http://127.0.0.1:9000/mcp"},
		},
		Policy: []Rule{
			{Upstream: "github", Allow: []Match{{Email: "ben@tail-scale.ts.net"}}},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

func TestValidateRejectsNonFunnelPort(t *testing.T) {
	c := &Config{
		Node: Node{Hostname: "tailgate", Port: 8080},
		OIDC: OIDC{Issuer: "https://idp.tail-scale.ts.net"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for non-Funnel port")
	}
}

func TestValidateRejectsUnknownPolicyUpstream(t *testing.T) {
	c := &Config{
		Node:   Node{Hostname: "tailgate", Port: 443},
		OIDC:   OIDC{Issuer: "https://idp.tail-scale.ts.net"},
		Policy: []Rule{{Upstream: "ghost"}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for policy referencing unknown upstream")
	}
}
