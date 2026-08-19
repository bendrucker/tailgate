package router

import (
	"net/http"
	"testing"
)

// Trailers are a second header map on the same request, so a name refused in
// the header arrives at the upstream anyway unless the trailers are cleared
// too. Every decision tailgate makes from a header falls to this: it validates
// the map it read while the upstream reads both.
func TestDispatchDropsTheCallerTrailers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		upstream  string
		transport func(*harness) *fakeTransport
	}{
		{name: "http upstream", upstream: httpUpstream, transport: func(h *harness) *fakeTransport { return h.httpUp }},
		{name: "stdio upstream", upstream: stdioUpstream, transport: func(h *harness) *fakeTransport { return h.stdioUp }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", tc.upstream)

			req := post("/mcp/"+tc.upstream, "good")
			req.Header.Set("Trailer", "Authorization, Mcp-Session-Id, Mcp-Method")
			req.Trailer = http.Header{
				"Authorization":  []string{"Bearer good"},
				"Mcp-Session-Id": []string{"someone-elses-session"},
				"Mcp-Method":     []string{"tools/call"},
			}

			h.serve(req)

			served := tc.transport(h).served()
			if len(served) != 1 {
				t.Fatalf("transport served %d requests, want 1", len(served))
			}
			if got := served[0].Trailer; len(got) != 0 {
				t.Errorf("upstream saw trailers %v, want none", got)
			}
			if got := served[0].Header.Get("Trailer"); got != "" {
				t.Errorf("upstream saw a Trailer announcement %q, want none", got)
			}
		})
	}
}

// A reverse proxy appends the caller's query to the target's rather than
// replacing it, so one that survived dispatch would add parameters to the URL
// the operator configured.
func TestDispatchDropsTheCallerQuery(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)

	if resp := h.serve(post("/mcp/"+httpUpstream+"?api_key=attacker&x=1", "good")); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	served := h.httpUp.served()
	if len(served) != 1 {
		t.Fatalf("transport served %d requests, want 1", len(served))
	}
	if got := served[0].URL.RawQuery; got != "" {
		t.Errorf("upstream saw query %q, want none", got)
	}
	if served[0].URL.ForceQuery {
		t.Error("upstream saw a forced empty query")
	}
}
