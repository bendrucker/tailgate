package resource

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChallenge(t *testing.T) {
	urls, err := NewURLs("tailgate.tail1234.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}

	for _, tc := range []struct {
		name     string
		upstream string
		opts     ChallengeOptions
		expected string
	}{
		{
			name:     "bare challenge",
			upstream: "github",
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/github", scope="openid email"`,
		},
		{
			name:     "invalid token",
			upstream: "github",
			opts:     ChallengeOptions{Error: "invalid_token"},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/github", scope="openid email", error="invalid_token"`,
		},
		{
			name:     "error with description",
			upstream: "linear",
			opts:     ChallengeOptions{Error: "invalid_token", ErrorDescription: "token audience does not include this resource"},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/linear", scope="openid email", error="invalid_token", error_description="token audience does not include this resource"`,
		},
		{
			name:     "description only",
			upstream: "linear",
			opts:     ChallengeOptions{ErrorDescription: "no bearer token"},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/linear", scope="openid email", error_description="no bearer token"`,
		},
		{
			name:     "quotes escaped",
			upstream: "github",
			opts:     ChallengeOptions{ErrorDescription: `token "abc" rejected`},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/github", scope="openid email", error_description="token \"abc\" rejected"`,
		},
		{
			name:     "backslash escaped",
			upstream: "github",
			opts:     ChallengeOptions{ErrorDescription: `a\b`},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/github", scope="openid email", error_description="a\\b"`,
		},
		{
			name:     "header injection dropped",
			upstream: "github",
			opts:     ChallengeOptions{Error: "invalid_token\r\nX-Evil: 1", ErrorDescription: "line\none"},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/github", scope="openid email", error="invalid_tokenX-Evil: 1", error_description="lineone"`,
		},
		{
			name:     "non ascii bytes dropped",
			upstream: "github",
			opts:     ChallengeOptions{ErrorDescription: "caf\u00e9 rejected"},
			expected: `Bearer resource_metadata="https://tailgate.tail1234.ts.net/.well-known/oauth-protected-resource/mcp/github", scope="openid email", error_description="caf rejected"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := urls.Challenge(tc.upstream, tc.opts); got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestChallengeOnNonDefaultPort(t *testing.T) {
	urls, err := NewURLs("tailgate.tail1234.ts.net", 8443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	expected := `Bearer resource_metadata="https://tailgate.tail1234.ts.net:8443/.well-known/oauth-protected-resource/mcp/github", scope="openid email"`
	if got := urls.Challenge("github", ChallengeOptions{}); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

// TestChallengeIsWritableHeader guards the sanitizing in quoteParam: net/http
// refuses to write a header value carrying control characters, which would turn
// a 401 into a dropped response.
func TestChallengeIsWritableHeader(t *testing.T) {
	urls, err := NewURLs("tailgate.tail1234.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	challenge := urls.Challenge("github", ChallengeOptions{
		Error:            "invalid_token",
		ErrorDescription: "bad\r\ninput\x00",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != challenge {
		t.Errorf("expected %s, got %s", challenge, got)
	}
}

// challengeParam extracts one quoted auth-param from a challenge value, the way
// a client reads resource_metadata back out.
func challengeParam(challenge, key string) (string, bool) {
	rest, ok := strings.CutPrefix(challenge, "Bearer ")
	if !ok {
		return "", false
	}
	for _, param := range strings.Split(rest, ", ") {
		name, value, ok := strings.Cut(param, "=")
		if !ok || name != key {
			continue
		}
		unquoted, ok := strings.CutPrefix(value, `"`)
		if !ok {
			return "", false
		}
		unquoted, ok = strings.CutSuffix(unquoted, `"`)
		if !ok {
			return "", false
		}
		return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(unquoted), true
	}
	return "", false
}
