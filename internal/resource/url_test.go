package resource

import "testing"

func TestResourceURL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fqdn     string
		port     int
		upstream string
		expected string
	}{
		{
			name:     "default port omitted",
			fqdn:     "tailgate.tail1234.ts.net",
			port:     443,
			upstream: "github",
			expected: "https://tailgate.tail1234.ts.net/mcp/github",
		},
		{
			name:     "non default port included",
			fqdn:     "tailgate.tail1234.ts.net",
			port:     8443,
			upstream: "github",
			expected: "https://tailgate.tail1234.ts.net:8443/mcp/github",
		},
		{
			name:     "trailing dot trimmed",
			fqdn:     "tailgate.tail1234.ts.net.",
			port:     443,
			upstream: "linear",
			expected: "https://tailgate.tail1234.ts.net/mcp/linear",
		},
		{
			name:     "host lowercased",
			fqdn:     "Tailgate.Tail1234.TS.NET",
			port:     443,
			upstream: "linear",
			expected: "https://tailgate.tail1234.ts.net/mcp/linear",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			urls, err := NewURLs(tc.fqdn, tc.port)
			if err != nil {
				t.Fatalf("NewURLs: %v", err)
			}
			if got := urls.ResourceURL(tc.upstream); got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestNewURLsRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		fqdn string
	}{
		{name: "empty", fqdn: ""},
		{name: "only dot", fqdn: "."},
		{name: "embedded path", fqdn: "host.ts.net/mcp"},
		{name: "embedded port", fqdn: "host.ts.net:443"},
		{name: "embedded query", fqdn: "host.ts.net?x=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewURLs(tc.fqdn, 443); err == nil {
				t.Errorf("expected error for %q", tc.fqdn)
			}
		})
	}
}

func TestMetadata(t *testing.T) {
	urls, err := NewURLs("tailgate.tail1234.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	expected := "/.well-known/oauth-protected-resource/mcp/github"
	if got := urls.Metadata("github"); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}
