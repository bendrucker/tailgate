package proxy

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStripCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
		want   http.Header
	}{
		{
			name:   "removes the bearer token",
			header: http.Header{"Authorization": {"Bearer opaque-token"}},
			want:   http.Header{},
		},
		{
			name:   "removes proxy credentials",
			header: http.Header{"Proxy-Authorization": {"Basic Zm9vOmJhcg=="}},
			want:   http.Header{},
		},
		{
			name: "removes every forwarding header",
			header: http.Header{
				"Forwarded":         {"for=203.0.113.9"},
				"X-Forwarded-For":   {"203.0.113.9"},
				"X-Forwarded-Host":  {"evil.example.com"},
				"X-Forwarded-Proto": {"http"},
				"X-Forwarded-Port":  {"8443"},
				"X-Forwarded-Ssl":   {"off"},
			},
			want: http.Header{},
		},
		{
			name:   "removes a spoofed identity header whatever its case",
			header: http.Header{"x-TAILGATE-subject": {"999"}},
			want:   http.Header{},
		},
		{
			name: "keeps protocol headers the upstream needs",
			header: http.Header{
				"Mcp-Session-Id":       {"abc"},
				"Mcp-Protocol-Version": {"2025-11-25"},
				"Content-Type":         {"application/json"},
				"Authorization":        {"Bearer opaque-token"},
			},
			want: http.Header{
				"Mcp-Session-Id":       {"abc"},
				"Mcp-Protocol-Version": {"2025-11-25"},
				"Content-Type":         {"application/json"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			StripCredentials(tc.header)
			if diff := cmp.Diff(tc.want, tc.header); diff != "" {
				t.Errorf("stripped header mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
