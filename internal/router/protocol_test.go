package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bendrucker/tailgate/internal/protocol"
)

const statelessMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`

// statelessPost builds an authorized POST as a 2026-07-28 client sends it,
// with the standard headers already mirroring the body.
func statelessPost(target, token, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(protocol.VersionHeader, string(protocol.Rev20260728))
	return req
}

func TestProtocolHeaderValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		headers map[string]string
		status  int
		reached bool
	}{
		{
			name:    "headers mirror the body",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search",` + statelessMeta + `}}`,
			headers: map[string]string{protocol.MethodHeader: "tools/call", protocol.NameHeader: "search"},
			status:  http.StatusOK,
			reached: true,
		},
		{
			name:    "method header names a different method than the body",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search",` + statelessMeta + `}}`,
			headers: map[string]string{protocol.MethodHeader: "tools/list"},
			status:  http.StatusBadRequest,
		},
		{
			name:    "name header names a different tool than the body",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all",` + statelessMeta + `}}`,
			headers: map[string]string{protocol.MethodHeader: "tools/call", protocol.NameHeader: "search"},
			status:  http.StatusBadRequest,
		},
		{
			name:    "required method header is absent",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + statelessMeta + `}}`,
			headers: nil,
			status:  http.StatusBadRequest,
		},
		{
			name:    "body declares a revision the header does not",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
			headers: map[string]string{protocol.MethodHeader: "tools/list"},
			status:  http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", httpUpstream)

			req := statelessPost("/mcp/"+httpUpstream, "good", tc.body)
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			resp := h.serve(req)

			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if reached := h.httpUp.count() > 0; reached != tc.reached {
				t.Errorf("upstream reached = %v, want %v", reached, tc.reached)
			}
		})
	}
}

// A refusal a modern client cannot recognize as modern talks it into falling
// back to the initialize handshake this revision removed.
func TestProtocolRefusalsAreJSONRPC(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		body    string
		method  string
		code    int
	}{
		{
			name:    "header mismatch",
			version: string(protocol.Rev20260728),
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + statelessMeta + `}}`,
			method:  "prompts/list",
			code:    protocol.CodeHeaderMismatch,
		},
		{
			name:    "revision tailgate does not speak",
			version: "2099-01-01",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			code:    protocol.CodeUnsupportedProtocolVersion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", httpUpstream)

			req := statelessPost("/mcp/"+httpUpstream, "good", tc.body)
			req.Header.Set(protocol.VersionHeader, tc.version)
			if tc.method != "" {
				req.Header.Set(protocol.MethodHeader, tc.method)
			}
			resp := h.serve(req)

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if contentType := resp.Header.Get("Content-Type"); contentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", contentType)
			}

			var body struct {
				JSONRPC string `json:"jsonrpc"`
				Error   struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.JSONRPC != "2.0" {
				t.Errorf("jsonrpc = %q, want 2.0", body.JSONRPC)
			}
			if body.Error.Code != tc.code {
				t.Errorf("error code = %d, want %d", body.Error.Code, tc.code)
			}
		})
	}
}

// A bodyless request has no pair that can disagree, so it reaches the
// transport that owes it a 405 rather than being refused as a mismatch.
func TestBodylessRequestSkipsHeaderValidation(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", stdioUpstream)

			req := httptest.NewRequest(method, "/mcp/"+stdioUpstream, nil)
			req.Header.Set("Authorization", "Bearer good")
			req.Header.Set(protocol.VersionHeader, string(protocol.Rev20260728))

			resp := h.serve(req)
			if resp.StatusCode == http.StatusBadRequest {
				t.Fatalf("status = 400, want the transport's own answer")
			}
			if h.stdioUp.count() == 0 {
				t.Error("request never reached the transport")
			}
		})
	}
}

// The router binds any session id a caller presents, whatever revision the
// request claims to speak, so declaring the revision that dropped the header
// is no way to shed the binding.
func TestSessionBindingSurvivesAClaimedRevision(t *testing.T) {
	h := newHarness(t)
	h.grant("alice", "1", "alice@example.com", httpUpstream)
	h.grant("mallory", "2", "mallory@example.com", httpUpstream)

	mintSession(h, "live-session")
	opened := h.serve(post("/mcp/"+httpUpstream, "alice"))
	if opened.StatusCode != http.StatusOK {
		t.Fatalf("opening status = %d, want 200", opened.StatusCode)
	}

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + statelessMeta + `}}`
	req := statelessPost("/mcp/"+httpUpstream, "mallory", body)
	req.Header.Set(protocol.MethodHeader, "tools/list")
	req.Header.Set(SessionHeader, "live-session")

	resp := h.serve(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for another identity's session", resp.StatusCode)
	}
}
