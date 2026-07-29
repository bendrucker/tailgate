package main

import (
	"strings"
	"testing"

	"github.com/bendrucker/tailgate/internal/config"
)

func TestExpectedFQDN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		node    config.Node
		joined  string
		wantErr bool
	}{
		{
			name:   "no expectation accepts any name",
			node:   config.Node{Hostname: "tailgate"},
			joined: "tailgate-4.example-name.ts.net.",
		},
		{
			name:   "expected name matches",
			node:   config.Node{Hostname: "tailgate", Tailnet: "example-name.ts.net"},
			joined: "tailgate.example-name.ts.net.",
		},
		{
			name:   "trailing dot and case do not matter",
			node:   config.Node{Hostname: "tailgate", Tailnet: "Example-Name.ts.net"},
			joined: "TAILGATE.example-name.ts.net",
		},
		{
			// A taken hostname comes back suffixed, which would shift every
			// resource URI away from the grant.
			name:    "control appended a suffix",
			node:    config.Node{Hostname: "tailgate", Tailnet: "example-name.ts.net"},
			joined:  "tailgate-1.example-name.ts.net.",
			wantErr: true,
		},
		{
			name:    "joined a different tailnet",
			node:    config.Node{Hostname: "tailgate", Tailnet: "example-name.ts.net"},
			joined:  "tailgate.other-name.ts.net.",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := expectedFQDN(tc.node, tc.joined)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tc.joined[:len(tc.joined)-1]) &&
					!strings.Contains(err.Error(), strings.ToLower(tc.joined)) {
					t.Errorf("expected the joined name in %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
