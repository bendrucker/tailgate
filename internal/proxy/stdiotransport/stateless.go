package stdiotransport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/protocol"
	"github.com/bendrucker/tailgate/internal/proxy"
)

// Methods the stateless revision defines that this transport handles itself
// rather than passing straight through.
const (
	// listenMethod opens the one long-lived stream the revision has left. Its
	// response is an SSE stream that stays open, so it is the one request whose
	// answer is not a single JSON object.
	listenMethod = "subscriptions/listen"
	// discoverMethod is the backward-compatibility probe the revision defines
	// for stdio: a child that answers it is of the stateless era, and one that
	// reports it unknown still expects the initialize handshake.
	discoverMethod = "server/discover"
)

// clientInfo identifies tailgate to a child that expects an initialize
// handshake. The child is talking to tailgate rather than to the caller.
var clientInfo = map[string]any{"name": "tailgate", "version": "0"}

// discoverParams carries what the revision expects on the era probe. A server
// that does implement server/discover reads its caller's version and
// capabilities out of _meta, and answers a probe that omits them as though the
// method itself were unknown, which reads back as the legacy answer.
func discoverParams() map[string]any {
	return map[string]any{
		"_meta": map[string]any{
			protocol.MetaProtocolVersion:    string(protocol.Rev20260728),
			protocol.MetaClientCapabilities: map[string]any{},
		},
	}
}

// statelessChild is one identity's child, and the in-progress attempt to start
// it. Concurrent first requests from one caller wait on the same attempt
// rather than each spawning a process.
type statelessChild struct {
	ready chan struct{}
	s     *session
	err   error
}

// serveStateless handles a POST from a client speaking a revision with no
// initialize handshake and no session header.
//
// Statelessness is the client's contract, not the child's. A stdio MCP server
// still holds state across messages and still costs a process, so the caller
// keeps one child rather than getting a fresh one per request. The cap and the
// idle reaper are unchanged, and the child is still reachable only by the
// identity it was started for.
func (t *Transport) serveStateless(w http.ResponseWriter, r *http.Request, inflight *proxy.InFlight, identity auth.Identity, msg message) {
	s, err := t.statelessSession(r.Context(), identity)
	if err != nil {
		if errors.Is(err, proxy.ErrCapExceeded) {
			t.audit.Deny(r.Context(), identity, t.options.Name, ReasonSessionCap)
		}
		t.writeError(w, err)
		return
	}
	defer s.finish()

	if !msg.IsRequest() {
		// Only a notification reaches the child unmodified. A message carrying
		// a correlation key but no method is neither request nor notification,
		// and forwarding it verbatim would put a caller-chosen id into the
		// namespace s.request mints from, where the child's answer to it would
		// satisfy another request's pending wait.
		if msg.Key != "" {
			t.writeError(w, errInvalidMessage)
			return
		}
		if err := s.send(msg.Line, t.options.RequestTimeout); err != nil {
			t.refuse(w, s, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if msg.Method == listenMethod {
		t.serveListen(w, inflight, s, msg)
		return
	}

	response, err := s.request(inflight.Context(), msg, t.options.RequestTimeout)
	if err != nil {
		t.refuse(w, s, err)
		return
	}
	writeJSON(w, response)
}

// drainNotifications writes whatever the stream has already buffered, and
// reports whether it may carry anything further.
func drainNotifications(stream *eventStream, l *listener) bool {
	for {
		select {
		case notification, open := <-l.notifications:
			if !open {
				return false
			}
			if err := stream.send(notification); err != nil {
				return false
			}
		default:
			return true
		}
	}
}

// statelessSession resolves the caller's child, starting it on first use.
//
// A child that has since died is not reused: the entry is retired and the next
// turn of the loop starts a fresh one, so a caller whose server crashed
// recovers on its next request rather than holding a name for a dead process.
func (t *Transport) statelessSession(ctx context.Context, identity auth.Identity) (*session, error) {
	for {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, proxy.ErrDraining
		}
		entry, ok := t.stateless[identity.Subject]
		if !ok {
			entry = &statelessChild{ready: make(chan struct{})}
			t.stateless[identity.Subject] = entry
			t.mu.Unlock()
			return t.startStateless(entry, identity)
		}
		t.mu.Unlock()

		select {
		case <-entry.ready:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		if entry.err != nil {
			return nil, entry.err
		}

		t.mu.Lock()
		if !entry.s.removed {
			entry.s.begin()
			t.mu.Unlock()
			return entry.s, nil
		}
		if t.stateless[identity.Subject] == entry {
			delete(t.stateless, identity.Subject)
		}
		t.mu.Unlock()
	}
}

// startStateless spawns the caller's child and brings it to a state where it
// answers requests, then publishes it to whoever is waiting. The returned
// session is already claimed for the request that started it.
func (t *Transport) startStateless(entry *statelessChild, identity auth.Identity) (*session, error) {
	s, err := t.newSession(identity)
	if err == nil {
		if err = t.handshake(s); err != nil {
			// A child that will not come up has no session to belong to, and
			// leaving it registered would hold the caller's cap slot.
			s.finish()
			t.removeSession(s)
			s = nil
		}
	}

	// A failed entry leaves the map before ready closes, and the fields the
	// waiters read are written before it too, so no waiter can wake onto a
	// child that never started.
	t.mu.Lock()
	if err != nil && t.stateless[identity.Subject] == entry {
		delete(t.stateless, identity.Subject)
	}
	entry.s, entry.err = s, err
	t.mu.Unlock()
	close(entry.ready)

	if err != nil {
		t.logger.Warn("stateless stdio child refused", "sub", identity.Subject, "err", err)
		return nil, err
	}
	t.logger.Info("stateless stdio child started", "sub", identity.Subject, "pid", s.cmd.Process.Pid)
	return s, nil
}

// handshake settles which era the child speaks and leaves it ready to serve.
//
// The probe is server/discover, which the revision defines for exactly this.
// A child that answers it needs nothing further. tailgate runs the older
// handshake on the caller's behalf for one that does not, because a stateless
// client will never send one.
//
// The fallback turns on whether the refusal is a code the revision itself
// defines, never on one specific code. A legacy child has no notion of the
// method and refuses however its runtime happens to: the SDKs answer -32601,
// -32602, or a code JSON-RPC does not define at all, and the revision forbids
// keying the fallback to any single one of them. Only a code from the reserved
// range identifies a child that implements the revision and declined anyway.
func (t *Transport) handshake(s *session) error {
	ctx, cancel := context.WithTimeout(context.Background(), t.options.RequestTimeout)
	defer cancel()

	response, err := s.call(ctx, discoverMethod, discoverParams(), t.options.RequestTimeout)
	if err != nil {
		return err
	}
	code, isError := errorCode(response)
	switch {
	case !isError:
		s.logger.Debug("stdio child answered server/discover")
		return nil
	case protocol.IsRevisionError(code):
		return fmt.Errorf("%w: stdio child refused server/discover with revision error %d", proxy.ErrUpstreamUnavailable, code)
	}
	s.logger.Debug("stdio child refused server/discover, so it predates the stateless era", "code", code)
	return t.initialize(ctx, s)
}

// initialize runs the handshake a pre-2026-07-28 child still requires before
// it will answer anything.
func (t *Transport) initialize(ctx context.Context, s *session) error {
	response, err := s.call(ctx, initializeMethod, map[string]any{
		"protocolVersion": string(protocol.LastHandshake),
		"capabilities":    map[string]any{},
		"clientInfo":      clientInfo,
	}, t.options.RequestTimeout)
	if err != nil {
		return err
	}
	if code, isError := errorCode(response); isError {
		return fmt.Errorf("%w: stdio child refused initialize with code %d", proxy.ErrUpstreamUnavailable, code)
	}
	if err := s.notify("notifications/initialized", map[string]any{}, t.options.RequestTimeout); err != nil {
		return err
	}
	s.logger.Debug("stdio child initialized against the pre-stateless handshake")
	return nil
}

// serveListen answers subscriptions/listen with the SSE stream that carries
// the child's notifications until the subscription ends.
//
// This is the one response the transport holds open, so it is the one exempt
// from the request timeout. The acknowledgement the child sends first is a
// notification and rides the stream like any other, and the JSON-RPC response
// is what ends the subscription rather than what opens it. Waiting for that
// response before writing any headers would hold every conforming child past
// the exchange deadline and then refuse it. Registering the stream before the
// request goes out is what keeps a notification the child emits immediately
// after from falling between the two.
func (t *Transport) serveListen(w http.ResponseWriter, inflight *proxy.InFlight, s *session, msg message) {
	l, unlisten := s.listen()
	defer unlisten()

	ended, release, err := s.subscribe(msg, t.options.RequestTimeout)
	if err != nil {
		t.refuse(w, s, err)
		return
	}
	defer release()

	stream := newEventStream(w)
	keepAlive := time.NewTicker(keepAliveInterval)
	defer keepAlive.Stop()
	for {
		select {
		case final := <-ended:
			// The child wrote the closing result after whatever it had already
			// emitted, but both arrive here on separate channels, so the queued
			// notifications go out first rather than losing a select race to
			// the message that ends the stream.
			if !drainNotifications(stream, l) {
				return
			}
			restored, err := setID(final, msg.ID)
			if err != nil {
				return
			}
			_ = stream.send(restored)
			return
		case notification, open := <-l.notifications:
			if !open {
				if s.overflowedStream(l) {
					t.logger.Warn("subscription stream closed because its client fell behind", "sub", s.subject)
				}
				return
			}
			if err := stream.send(notification); err != nil {
				return
			}
		case <-keepAlive.C:
			if err := stream.comment(); err != nil {
				return
			}
		case <-inflight.Context().Done():
			return
		}
	}
}
