package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/protocol"
)

// outcomes renders each recorded decision as "outcome:reason", which is what a
// test asserting that a refusal was audited needs and nothing more.
func (c *auditCollector) outcomes() []string {
	rendered := []string{}
	for _, record := range c.decisions() {
		rendered = append(rendered, record.Outcome+":"+record.Reason)
	}
	return rendered
}

// errReader fails every read, standing in for a client that hangs up partway
// through its body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// TestPipelineOrder pins the sequence an upstream request passes. Two of these
// positions are load-bearing and neither is enforced by a type: body limiting
// and protocol validation must follow authentication, and protocol validation
// must follow body limiting because it reads the body that step buffered.
func TestPipelineOrder(t *testing.T) {
	h := newHarness(t)

	if got := h.router.origin.name(); got != "origin" {
		t.Errorf("origin step = %q, want the origin check ahead of routing", got)
	}

	want := []string{"authenticate", "authorize", "session", "body", "protocol"}
	got := []string{}
	for _, s := range h.router.pipeline {
		got = append(got, s.name())
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("pipeline order mismatch (-want +got):\n%s", diff)
	}
}

// TestAuthenticationPrecedesEveryOtherCheck holds the two orderings the
// security argument rests on. An authentication decision must not turn on a
// body the caller chose, and an unauthenticated caller must learn nothing
// about the upstream's protocol shape from the shape of a refusal. Each
// request here would be refused by a later step on its own merits, so moving
// that step above authentication swaps the 401 for the later step's answer.
func TestAuthenticationPrecedesEveryOtherCheck(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func() *http.Request
	}{
		{
			name: "body over the cap",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/mcp/"+httpUpstream, strings.NewReader(strings.Repeat("a", 200)))
			},
		},
		{
			name: "revision tailgate does not speak",
			request: func() *http.Request {
				req := post("/mcp/"+httpUpstream, "")
				req.Header.Set(protocol.VersionHeader, "2099-01-01")
				return req
			},
		},
		{
			name: "mirrored headers disagreeing with the body",
			request: func() *http.Request {
				req := post("/mcp/"+httpUpstream, "")
				req.Header.Set(protocol.VersionHeader, string(protocol.Rev20260728))
				req.Header.Set(protocol.MethodHeader, "tools/list")
				return req
			},
		},
		{
			name: "repeated session header",
			request: func() *http.Request {
				req := post("/mcp/"+httpUpstream, "")
				req.Header.Add(SessionHeader, "one")
				req.Header.Add(SessionHeader, "two")
				return req
			},
		},
		{
			name: "session the router holds no binding for",
			request: func() *http.Request {
				return withSession(post("/mcp/"+httpUpstream, ""), "invented")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *Options) { o.MaxBodyBytes = 64 })

			resp := h.serve(tc.request())
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 before any later step answers", resp.StatusCode)
			}
			if h.httpUp.count() != 0 {
				t.Error("an unauthenticated request reached the transport")
			}
			want := []string{audit.OutcomeDeny + ":" + ReasonNoToken}
			if diff := cmp.Diff(want, h.audit.outcomes()); diff != "" {
				t.Errorf("audit mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRefusals is the whole refusal surface in one place: what each one
// answers, in which body format, and what it leaves in the decision log. A
// refusal that skips its audit record or answers 400 in bare text shows up
// here as a diff rather than as a silent gap.
func TestRefusals(t *testing.T) {
	allowed := audit.OutcomeAllow + ":" + auth.ReasonMatched

	for _, tc := range []struct {
		name    string
		setup   func(*harness)
		request func(*harness) *http.Request
		status  int
		// code is the JSON-RPC error code the body carries, and zero means the
		// refusal answers in status text.
		code    int
		audited []string
	}{
		{
			name: "origin tailgate is not served from",
			request: func(h *harness) *http.Request {
				req := post("/mcp/"+httpUpstream, "good")
				req.Header.Set("Origin", "https://evil.example.com")
				return req
			},
			status:  http.StatusForbidden,
			audited: []string{audit.OutcomeDeny + ":" + ReasonOriginNotAllowed},
		},
		{
			name: "path naming no configured upstream",
			request: func(h *harness) *http.Request {
				return post("/mcp/nope", "good")
			},
			status:  http.StatusNotFound,
			audited: []string{},
		},
		{
			name: "no bearer token",
			request: func(h *harness) *http.Request {
				return post("/mcp/"+httpUpstream, "")
			},
			status:  http.StatusUnauthorized,
			audited: []string{audit.OutcomeDeny + ":" + ReasonNoToken},
		},
		{
			name: "credential that is not a bearer token",
			request: func(h *harness) *http.Request {
				req := post("/mcp/"+httpUpstream, "")
				req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
				return req
			},
			status:  http.StatusUnauthorized,
			audited: []string{audit.OutcomeDeny + ":" + ReasonMalformedAuthorization},
		},
		{
			name: "token the issuer does not know",
			request: func(h *harness) *http.Request {
				return post("/mcp/"+httpUpstream, "forged")
			},
			status:  http.StatusUnauthorized,
			audited: []string{audit.OutcomeDeny + ":" + ReasonInvalidToken},
		},
		{
			name:  "token missing a required scope",
			setup: func(h *harness) { h.verifier.err = fmt.Errorf("%w: no email", auth.ErrInsufficientScope) },
			request: func(h *harness) *http.Request {
				return post("/mcp/"+httpUpstream, "good")
			},
			status:  http.StatusForbidden,
			audited: []string{audit.OutcomeDeny + ":" + ReasonInsufficientScope},
		},
		{
			name:  "verification tailgate cannot complete",
			setup: func(h *harness) { h.verifier.err = auth.ErrUnavailable },
			request: func(h *harness) *http.Request {
				return post("/mcp/"+httpUpstream, "good")
			},
			status:  http.StatusServiceUnavailable,
			audited: []string{audit.OutcomeDeny + ":" + ReasonVerifierUnavailable},
		},
		{
			name: "identity no policy rule allows",
			request: func(h *harness) *http.Request {
				return post("/mcp/"+stdioUpstream, "good")
			},
			status:  http.StatusForbidden,
			audited: []string{audit.OutcomeDeny + ":" + auth.ReasonNoMatch},
		},
		{
			name: "repeated session header",
			request: func(h *harness) *http.Request {
				req := post("/mcp/"+httpUpstream, "good")
				req.Header.Add(SessionHeader, "one")
				req.Header.Add(SessionHeader, "two")
				return req
			},
			status:  http.StatusBadRequest,
			code:    protocol.CodeInvalidRequest,
			audited: []string{allowed, audit.OutcomeDeny + ":" + ReasonSessionAmbiguous},
		},
		{
			name: "session the router holds no binding for",
			request: func(h *harness) *http.Request {
				return withSession(post("/mcp/"+httpUpstream, "good"), "invented")
			},
			status:  http.StatusNotFound,
			audited: []string{allowed, audit.OutcomeDeny + ":" + ReasonSessionUnrecognized},
		},
		{
			name: "body over the cap",
			request: func(h *harness) *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/mcp/"+httpUpstream, strings.NewReader(strings.Repeat("a", 200)))
				req.Header.Set("Authorization", "Bearer good")
				return req
			},
			status:  http.StatusRequestEntityTooLarge,
			audited: []string{allowed},
		},
		{
			name: "body tailgate could not read",
			request: func(h *harness) *http.Request {
				req := post("/mcp/"+httpUpstream, "good")
				req.Body = io.NopCloser(errReader{})
				return req
			},
			status:  http.StatusBadRequest,
			code:    protocol.CodeParseError,
			audited: []string{allowed},
		},
		{
			name: "revision tailgate does not speak",
			request: func(h *harness) *http.Request {
				req := post("/mcp/"+httpUpstream, "good")
				req.Header.Set(protocol.VersionHeader, "2099-01-01")
				return req
			},
			status:  http.StatusBadRequest,
			code:    protocol.CodeUnsupportedProtocolVersion,
			audited: []string{allowed},
		},
		{
			name: "mirrored headers disagreeing with the body",
			request: func(h *harness) *http.Request {
				req := post("/mcp/"+httpUpstream, "good")
				req.Header.Set(protocol.VersionHeader, string(protocol.Rev20260728))
				req.Header.Set(protocol.MethodHeader, "tools/list")
				return req
			},
			status:  http.StatusBadRequest,
			code:    protocol.CodeHeaderMismatch,
			audited: []string{allowed},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *Options) { o.MaxBodyBytes = 64 })
			h.grant("good", "42", "user@example.com", httpUpstream)
			if tc.setup != nil {
				tc.setup(h)
			}

			resp := h.serve(tc.request(h))
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if h.httpUp.count()+h.stdioUp.count() != 0 {
				t.Error("a refused request reached a transport")
			}
			if diff := cmp.Diff(tc.audited, h.audit.outcomes()); diff != "" {
				t.Errorf("audit mismatch (-want +got):\n%s", diff)
			}

			// The rule the refusal type enforces: 400 is the one status a
			// probing client reads as a statement about the server's protocol
			// era, so every 400 answers as a JSON-RPC error and nothing else
			// does.
			if wantJSONRPC := tc.status == http.StatusBadRequest; wantJSONRPC != (tc.code != 0) {
				t.Fatalf("case expects code %d at status %d, which is not the format rule", tc.code, tc.status)
			}
			if tc.code == 0 {
				if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
					t.Errorf("Content-Type = %q, want text/plain", contentType)
				}
				return
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

// TestRefusalFormatFollowsStatus covers the shapes no step builds today. The
// status alone decides the body format, so a 400 answers as a JSON-RPC error
// even when the step that built it reached for a text constructor or left the
// error object's code unset. TestRefusals holds the rule for the refusals the
// pipeline actually produces.
func TestRefusalFormatFollowsStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  *refusal
		code int
	}{
		{
			name: "text constructor at bad request",
			ref:  refuse(http.StatusBadRequest, "bad request"),
			code: protocol.CodeInvalidRequest,
		},
		{
			name: "protocol constructor without a code",
			ref:  refuseProtocol(protocol.ErrorObject{Message: "mismatch"}),
			code: protocol.CodeInvalidRequest,
		},
		{
			name: "protocol constructor with a code",
			ref:  refuseProtocol(protocol.UnsupportedVersion("1999-01-01")),
			code: protocol.CodeUnsupportedProtocolVersion,
		},
		{
			name: "text constructor at another status",
			ref:  refuse(http.StatusForbidden, "forbidden"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.ref.write(rec)

			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tc.ref.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.ref.status)
			}
			if tc.code == 0 {
				if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
					t.Errorf("Content-Type = %q, want text/plain", contentType)
				}
				return
			}
			if contentType := resp.Header.Get("Content-Type"); contentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", contentType)
			}
			var body struct {
				JSONRPC string `json:"jsonrpc"`
				Error   struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
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
			if body.Error.Message == "" {
				t.Error("error message is empty")
			}
		})
	}
}
