package router

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
)

// mintSession makes the HTTP upstream answer every request with sessionID, the
// way a streamable HTTP MCP server answers initialize.
func mintSession(h *harness, sessionID string) {
	h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(SessionHeader, sessionID)
		w.WriteHeader(http.StatusOK)
	}
}

func withSession(req *http.Request, sessionID string) *http.Request {
	req.Header.Set(SessionHeader, sessionID)
	return req
}

func TestSessionBoundToAnotherIdentityIsRefused(t *testing.T) {
	h := newHarness(t)
	h.grant("token-a", "42", "a@example.com", httpUpstream)
	h.grant("token-b", "77", "b@example.com", httpUpstream)
	mintSession(h, "session-a")

	if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}
	served := h.httpUp.count()

	resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-b"), "session-a"))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("hijack status = %d, want 404", resp.StatusCode)
	}
	if h.httpUp.count() != served {
		t.Error("hijacked session reached the transport")
	}

	if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "session-a")); resp.StatusCode != http.StatusOK {
		t.Errorf("owner status = %d, want 200", resp.StatusCode)
	}

	want := []auditRecord{
		{Level: slog.LevelInfo.String(), Outcome: audit.OutcomeAllow, Subject: "42", Email: "a@example.com", Upstream: httpUpstream, Reason: auth.ReasonMatched, Rule: "policy[0].allow[0]"},
		{Level: slog.LevelInfo.String(), Outcome: audit.OutcomeAllow, Subject: "77", Email: "b@example.com", Upstream: httpUpstream, Reason: auth.ReasonMatched, Rule: "policy[0].allow[0]"},
		{Level: slog.LevelWarn.String(), Outcome: audit.OutcomeDeny, Subject: "77", Email: "b@example.com", Upstream: httpUpstream, Reason: ReasonSessionBound},
		{Level: slog.LevelInfo.String(), Outcome: audit.OutcomeAllow, Subject: "42", Email: "a@example.com", Upstream: httpUpstream, Reason: auth.ReasonMatched, Rule: "policy[0].allow[0]"},
	}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

func TestUnrecordedSessionIsRefused(t *testing.T) {
	h := newHarness(t)
	h.grant("token-a", "42", "a@example.com", httpUpstream)

	resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "orphan"))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404: a session the router never recorded is not claimable", resp.StatusCode)
	}
	if h.httpUp.count() != 0 {
		t.Error("an unrecorded session reached the transport")
	}

	want := []auditRecord{
		{Level: slog.LevelInfo.String(), Outcome: audit.OutcomeAllow, Subject: "42", Email: "a@example.com", Upstream: httpUpstream, Reason: auth.ReasonMatched, Rule: "policy[0].allow[0]"},
		{Level: slog.LevelWarn.String(), Outcome: audit.OutcomeDeny, Subject: "42", Email: "a@example.com", Upstream: httpUpstream, Reason: ReasonSessionUnrecognized},
	}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

// A caller who could put session IDs of its own choosing in the table would
// flood it until the binding guarding someone else's live session is evicted,
// and then take that session over.
func TestPresentedSessionsCannotEvictABinding(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxSessions = 4 })
	h.grant("token-a", "42", "a@example.com", httpUpstream)
	h.grant("token-b", "77", "b@example.com", httpUpstream)
	mintSession(h, "session-a")

	if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}
	served := h.httpUp.count()

	for i := range 64 {
		resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-b"), "flood-"+strconv.Itoa(i)))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("flood %d status = %d, want 404", i, resp.StatusCode)
		}
	}
	if h.httpUp.count() != served {
		t.Error("an invented session ID reached the transport")
	}

	if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-b"), "session-a")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("hijack after flood status = %d, want 404", resp.StatusCode)
	}
	if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "session-a")); resp.StatusCode != http.StatusOK {
		t.Errorf("owner status = %d, want 200: the flood evicted a live binding", resp.StatusCode)
	}
}

func TestSessionsAreScopedPerUpstream(t *testing.T) {
	h := newHarness(t)
	h.grant("token-a", "42", "a@example.com", httpUpstream)
	h.grant("token-b", "77", "b@example.com", httpUpstream, stdioUpstream)
	mintSession(h, "shared-id")

	if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}
	// stdiotransport binds identity to its own synthesized sessions, so the
	// router leaves that upstream's session header alone.
	resp := h.serve(withSession(post("/mcp/"+stdioUpstream, "token-b"), "shared-id"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200: an unbound upstream must not inherit another upstream's binding", resp.StatusCode)
	}
	if h.stdioUp.count() != 1 {
		t.Error("request never reached the stdio transport")
	}
}

func TestSessionBindingReleasedOnDelete(t *testing.T) {
	h := newHarness(t)
	h.grant("token-a", "42", "a@example.com", httpUpstream)
	mintSession(h, "session-a")

	if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}

	h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	del := withSession(post("/mcp/"+httpUpstream, "token-a"), "session-a")
	del.Method = http.MethodDelete
	if resp := h.serve(del); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", resp.StatusCode)
	}
	served := h.httpUp.count()

	h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "session-a")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404: a terminated session's binding must not outlive it", resp.StatusCode)
	}
	if h.httpUp.count() != served {
		t.Error("a terminated session reached the transport")
	}
}

func TestSessionBindingReleasedWhenUpstreamForgetsIt(t *testing.T) {
	h := newHarness(t)
	h.grant("token-a", "42", "a@example.com", httpUpstream)
	mintSession(h, "session-a")

	if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}

	h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }
	if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "session-a")); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("upstream status = %d, want 404", resp.StatusCode)
	}
	served := h.httpUp.count()

	h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "session-a")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404: a session the upstream no longer knows must not stay bound", resp.StatusCode)
	}
	if h.httpUp.count() != served {
		t.Error("a released session reached the transport")
	}
}

// An MCP server commonly echoes the session ID it was handed when it rejects a
// request, so the status guard is what keeps a rejected request from becoming
// a lasting claim on a session the upstream never issued.
func TestSessionNotRecordedOnUpstreamError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "unknown session", status: http.StatusNotFound},
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "bad request", status: http.StatusBadRequest},
		{name: "upstream failure", status: http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("token-a", "42", "a@example.com", httpUpstream)
			h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(SessionHeader, "echoed")
				w.WriteHeader(tc.status)
			}

			if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != tc.status {
				t.Fatalf("upstream status = %d, want %d", resp.StatusCode, tc.status)
			}
			served := h.httpUp.count()

			h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
			if resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-a"), "echoed")); resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404: a rejected request must not bind the session it echoed", resp.StatusCode)
			}
			if h.httpUp.count() != served {
				t.Error("the echoed session reached the transport")
			}
		})
	}
}

func TestSessionBindingSkippedForUnboundUpstream(t *testing.T) {
	h := newHarness(t)
	h.grant("token-a", "42", "a@example.com", stdioUpstream)
	h.grant("token-b", "77", "b@example.com", stdioUpstream)

	for _, token := range []string{"token-a", "token-b"} {
		resp := h.serve(withSession(post("/mcp/"+stdioUpstream, token), "stdio-session"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", token, resp.StatusCode)
		}
	}
	if h.stdioUp.count() != 2 {
		t.Errorf("stdio transport served %d requests, want 2", h.stdioUp.count())
	}
}

// TestSessionBindingIsOnUnlessWaived pins the default: an upstream declared
// with nothing but a name and a transport binds its sessions, so wiring that
// forgets to think about session ownership gets the protection.
func TestSessionBindingIsOnUnlessWaived(t *testing.T) {
	for _, tc := range []struct {
		name    string
		waive   bool
		hijack  int
		reached int
	}{
		{name: "declared with no session opinion", hijack: http.StatusNotFound, reached: 1},
		{name: "transport manages its own sessions", waive: true, hijack: http.StatusOK, reached: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *Options) {
				for i := range o.Upstreams {
					if o.Upstreams[i].Name == httpUpstream {
						o.Upstreams[i].TransportManagesSessions = tc.waive
					}
				}
			})
			h.grant("token-a", "42", "a@example.com", httpUpstream)
			h.grant("token-b", "77", "b@example.com", httpUpstream)
			mintSession(h, "session-a")

			if resp := h.serve(post("/mcp/"+httpUpstream, "token-a")); resp.StatusCode != http.StatusOK {
				t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
			}
			resp := h.serve(withSession(post("/mcp/"+httpUpstream, "token-b"), "session-a"))
			if resp.StatusCode != tc.hijack {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.hijack)
			}
			if h.httpUp.count() != tc.reached {
				t.Errorf("transport served %d requests, want %d", h.httpUp.count(), tc.reached)
			}
		})
	}
}

func TestSessionBindingsEvictAndExpire(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	t.Run("eviction bounds the table", func(t *testing.T) {
		bindings := newSessionBindings(2, time.Hour, clock)
		for i := range 3 {
			bindings.bind(sessionKey("docs", strconv.Itoa(i)), "42")
		}
		if got := bindings.order.Len(); got != 2 {
			t.Errorf("table holds %d bindings, want the 2 it was capped at", got)
		}
		if _, bound := bindings.holds(sessionKey("docs", "0"), "42"); bound {
			t.Error("the oldest binding survived the cap")
		}
		if allowed, _ := bindings.holds(sessionKey("docs", "2"), "42"); !allowed {
			t.Error("the most recent binding was evicted instead of the oldest")
		}
	})

	t.Run("a presented session inserts nothing", func(t *testing.T) {
		bindings := newSessionBindings(2, time.Hour, clock)
		bindings.bind(sessionKey("docs", "live"), "42")

		for i := range 16 {
			if allowed, bound := bindings.holds(sessionKey("docs", "flood-"+strconv.Itoa(i)), "77"); allowed || bound {
				t.Fatalf("flood %d: allowed = %v, bound = %v, want both false", i, allowed, bound)
			}
		}
		if got := bindings.order.Len(); got != 1 {
			t.Errorf("table holds %d bindings, want only the one the upstream minted", got)
		}
		if allowed, _ := bindings.holds(sessionKey("docs", "live"), "42"); !allowed {
			t.Error("the flood evicted a binding the upstream minted")
		}
	})

	t.Run("expiry forfeits a quiet binding", func(t *testing.T) {
		bindings := newSessionBindings(8, time.Minute, clock)
		bindings.bind(sessionKey("docs", "quiet"), "42")
		advance(30 * time.Second)
		if allowed, _ := bindings.holds(sessionKey("docs", "quiet"), "42"); !allowed {
			t.Fatal("the holder was refused before the ttl elapsed")
		}
		advance(30 * time.Second)
		if allowed, _ := bindings.holds(sessionKey("docs", "quiet"), "42"); !allowed {
			t.Fatal("use did not refresh the binding")
		}
		advance(2 * time.Minute)
		if _, bound := bindings.holds(sessionKey("docs", "quiet"), "42"); bound {
			t.Error("an expired binding still holds its session")
		}
	})

	t.Run("release forgets a binding", func(t *testing.T) {
		bindings := newSessionBindings(8, time.Hour, clock)
		bindings.bind(sessionKey("docs", "gone"), "42")
		bindings.release(sessionKey("docs", "gone"))
		if _, bound := bindings.holds(sessionKey("docs", "gone"), "42"); bound {
			t.Error("a released binding still holds its session")
		}
	})
}

func TestSessionBindingsAreConcurrencySafe(t *testing.T) {
	bindings := newSessionBindings(64, time.Hour, nil)

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := sessionKey("docs", strconv.Itoa(i%8))
			bindings.bind(key, strconv.Itoa(i))
			bindings.holds(key, strconv.Itoa(i))
			bindings.release(key)
		}()
	}
	wg.Wait()
}
