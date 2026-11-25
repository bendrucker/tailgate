package stdiotransport

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestCapEvictsLeastRecentlyUsedIdleSession(t *testing.T) {
	h := newHarness(t, Options{MaxSessions: 2, IdleTimeout: time.Hour})
	older := h.initialize(t, "alice")
	newer := h.initialize(t, "alice")

	touched := h.do(t, call{subject: "alice", session: older, body: requestBody(2, "tools/list", "")})
	touched.Body.Close()
	if touched.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", touched.StatusCode)
	}

	h.initialize(t, "alice")

	evicted := h.do(t, call{subject: "alice", session: newer, body: requestBody(3, "tools/list", "")})
	evicted.Body.Close()
	if evicted.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for the evicted session, got %d", evicted.StatusCode)
	}
	kept := h.do(t, call{subject: "alice", session: older, body: requestBody(4, "tools/list", "")})
	kept.Body.Close()
	if kept.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for the recently used session, got %d", kept.StatusCode)
	}
	if slots := h.transport.reservedSlots("alice"); slots != 2 {
		t.Errorf("expected the cap to hold at 2 slots, got %d", slots)
	}
}

func TestCapNeverEvictsABusySession(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{MaxSessions: 2, IdleTimeout: time.Hour}, held.answer)
	busy := h.initialize(t, "alice")
	busyChild := h.children.next(t)
	idle := h.initialize(t, "alice")

	answered := make(chan int, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: busy, body: requestBody(2, "tools/call", "held")})
		defer response.Body.Close()
		answered <- response.StatusCode
	}()
	inflight := held.next(t)
	// The busy session is the least recently used one, so only its request in
	// flight keeps it from being chosen.
	h.session(t, busy).lastUsed.Store(0)

	h.initialize(t, "alice")

	evicted := h.do(t, call{subject: "alice", session: idle, body: requestBody(3, "tools/list", "")})
	evicted.Body.Close()
	if evicted.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for the idle session, got %d", evicted.StatusCode)
	}
	busyChild.result(inflight, `{"echo":"held"}`)
	if status := <-answered; status != http.StatusOK {
		t.Errorf("expected the busy session's request to complete, got %d", status)
	}
}

func TestCapRefusesWhenEverySessionIsBusy(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{MaxSessions: 1, IdleTimeout: time.Hour}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	answered := make(chan int, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/call", "held")})
		defer response.Body.Close()
		answered <- response.StatusCode
	}()
	inflight := held.next(t)

	refused := h.do(t, call{subject: "alice", body: `{"jsonrpc":"2.0","id":"init-7","method":"initialize","params":{}}`})
	defer refused.Body.Close()
	if refused.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", refused.StatusCode)
	}
	if contentType := refused.Header.Get("Content-Type"); contentType != "application/json" {
		t.Errorf("expected application/json, got %q", contentType)
	}
	want := map[string]any{
		"jsonrpc": "2.0",
		"id":      "init-7",
		"error":   map[string]any{"code": float64(-32000), "message": capMessage},
	}
	if diff := cmp.Diff(want, decodeMessage(t, refused)); diff != "" {
		t.Errorf("refusal body mismatch (-want +got):\n%s", diff)
	}

	child.result(inflight, `{"echo":"held"}`)
	if status := <-answered; status != http.StatusOK {
		t.Errorf("expected the busy session to keep serving, got %d", status)
	}
}

func TestCapNeverEvictsAChildHoldingASubscription(t *testing.T) {
	held := holdingSubscriptions()
	h := newScriptedHarness(t, Options{MaxSessions: 1, IdleTimeout: time.Hour}, held.answer)

	responses := make(chan *http.Response, 1)
	go func() {
		responses <- h.do(t, call{subject: "alice", protocol: stateless, body: statelessBody("listen-1", listenMethod, "")})
	}()
	child := h.children.next(t)
	listen := held.next(t)
	stream := <-responses
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("expected the subscription to open, got %d", stream.StatusCode)
	}

	refused := h.do(t, call{subject: "alice", body: initializeBody})
	refused.Body.Close()
	if refused.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while the subscription is open, got %d", refused.StatusCode)
	}

	child.result(listen, `{"ended":true}`)
	if final := readEvents(t, stream, 2)[1]; final["id"] != "listen-1" {
		t.Errorf("expected the subscription to end normally, got %v", final)
	}
}

func TestCapEvictsAnIdleStatelessChild(t *testing.T) {
	h := newHarness(t, Options{MaxSessions: 1, IdleTimeout: time.Hour})
	first := h.do(t, call{subject: "alice", protocol: stateless, body: statelessBody(1, "tools/list", "")})
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", first.StatusCode)
	}
	statelessChild := h.children.next(t)

	h.initialize(t, "alice")
	awaitClose(t, statelessChild.exited, "the stateless child to be evicted")
}
