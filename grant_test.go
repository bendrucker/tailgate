package main

import (
	"testing"

	"github.com/bendrucker/tailgate/internal/config"
	"github.com/google/go-cmp/cmp"
)

// TestOrPolicyUsers covers the second gate on an upstream. tsidp's users field
// decides who may mint a token naming an upstream's audience, and tailgate's
// policy decides who may spend one. A wildcard on the first leaves the second
// standing alone.
func TestOrPolicyUsers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		explicit []string
		policy   []config.Rule
		want     []string
	}{
		{
			name: "no policy leaves the grant at its default",
		},
		{
			name:     "an explicit flag wins over the policy",
			explicit: []string{"ben@example.com"},
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{{Email: "someone@example.com"}}},
			},
			want: []string{"ben@example.com"},
		},
		{
			name: "emails carry into the grant",
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{{Email: "ben@example.com"}}},
			},
			want: []string{"ben@example.com"},
		},
		{
			name: "subjects carry into the grant",
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{{Subject: "12345"}}},
			},
			want: []string{"12345"},
		},
		{
			name: "an identity named twice appears once",
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{{Email: "ben@example.com"}}},
				{Upstream: "files", Allow: []config.Match{{Email: "ben@example.com"}}},
			},
			want: []string{"ben@example.com"},
		},
		{
			name: "every identity across every upstream",
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{
					{Email: "ben@example.com"},
					{Subject: "12345"},
				}},
				{Upstream: "files", Allow: []config.Match{{Email: "sam@example.com"}}},
			},
			want: []string{"ben@example.com", "12345", "sam@example.com"},
		},
		{
			name: "a match on both names both",
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{{Email: "ben@example.com", Subject: "12345"}}},
			},
			want: []string{"ben@example.com", "12345"},
		},
		{
			// A claim condition allows an identity the grant cannot name, and a
			// grant narrower than the policy denies before tailgate ever sees
			// the request.
			name: "a claim condition falls back to the default",
			policy: []config.Rule{
				{Upstream: "github", Allow: []config.Match{{Email: "ben@example.com"}}},
				{Upstream: "files", Allow: []config.Match{{Claim: map[string]string{"scope": "openid"}}}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, orPolicyUsers(tc.explicit, tc.policy)); diff != "" {
				t.Errorf("grant users (-want +got):\n%s", diff)
			}
		})
	}
}
