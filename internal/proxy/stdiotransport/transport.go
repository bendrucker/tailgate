// Package stdiotransport serves streamable HTTP over a child process.
//
// A stdio MCP server speaks JSON-RPC over its own pipes and has no notion of
// HTTP, sessions, or protocol revisions, so this transport is the server side
// of the HTTP protocol: it correlates JSON-RPC ids across the child's
// newline-delimited stream and reaps children that go idle. Because a request
// here spawns a process, the caps and lifecycles live per identity: one caller
// cannot exhaust the host for others.
//
// # The child
//
// A child is reached through the Child interface: send a message, receive
// messages, wait for the exit, end it. A configured upstream gets execChild,
// which runs Options.Command in a process group of its own and under the uid
// the upstream names. Options.StartChild replaces that constructor, so a test
// drives a child answering in tailgate's own address space rather than one on
// the far end of a pipe.
//
// # Two eras of caller
//
// What a child is addressed by depends on the revision the request declares.
// Through 2025-11-25 a caller opens a session with initialize, gets a minted
// Mcp-Session-Id bound to its identity, and reaches one child per session. A
// 2026-07-28 caller has neither, so it reaches one child per identity, started
// on first use.
//
// That child is the same kind of program either way, and it holds state across
// messages whatever HTTP has decided. So the stateless path supplies what the
// caller no longer does: it settles the child's own era with the revision's
// server/discover probe, and runs the initialize handshake itself for a child
// that predates the revision.
//
// # Correlation ids
//
// A caller's JSON-RPC id never reaches the child. Every request tailgate
// carries goes out under an id it mints and comes back restored, whichever era
// the caller speaks. A session is no id space of its own: independent POSTs
// may all call themselves id 1, and a caller that hangs up mid-request and
// retries reuses an id the child is still working on. Correlating on the
// caller's id would let either request take the other's answer.
//
// # Notifications
//
// A child's notifications reach a client only on the response stream of a
// subscriptions/listen request, which is the one response this transport holds
// open and therefore the one exempt from the exchange timeout. With no such
// stream open, a notification has nowhere to go and is dropped.
//
// The no-token-passthrough invariant holds by construction here. Nothing from
// the client's HTTP request reaches the child but the JSON-RPC message itself,
// so there is no header for a credential to ride on.
package stdiotransport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/protocol"
	"github.com/bendrucker/tailgate/internal/proxy"
)

// Defaults applied to zero-valued Options.
const (
	// DefaultMaxSessions caps live sessions per identity per upstream.
	DefaultMaxSessions = 4
	// DefaultIdleTimeout reaps a session whose caller has gone away without
	// sending DELETE.
	DefaultIdleTimeout = 5 * time.Minute
	// DefaultRequestTimeout bounds one JSON-RPC exchange with a child.
	DefaultRequestTimeout = time.Minute
	// DefaultKeepAliveInterval is how often a quiet subscription stream says
	// something, so nothing between tailgate and the client closes it.
	DefaultKeepAliveInterval = 30 * time.Second
)

// AssumedProtocolVersion is the version a request without an
// MCP-Protocol-Version header is treated as speaking.
const AssumedProtocolVersion = protocol.Assumed

// maxBodyBytes bounds a POSTed message. The router applies its own limit;
// this one and the read deadline servePost sets keep the transport safe on its
// own, in size and in duration.
const maxBodyBytes = 4 << 20

const (
	sessionHeader         = protocol.SessionHeader
	protocolVersionHeader = protocol.VersionHeader
	initializeMethod      = "initialize"
)

var (
	errMissingSessionID = errors.New("stdiotransport: Mcp-Session-Id is required")
	errAmbiguousSession = errors.New("stdiotransport: Mcp-Session-Id is present more than once")
	errUnauthenticated  = errors.New("stdiotransport: request carries no authorized identity")
	errBodyTooLarge     = errors.New("stdiotransport: request body exceeds the message limit")
	errBodyTimeout      = errors.New("stdiotransport: request body was not sent in time")
)

// Reasons recorded on the audit log for refusals this transport makes itself.
// The router binds sessions only for upstreams whose transport passes the
// upstream's own session ids through, so a stdio session's own refusals are
// the only record of them. ReasonSessionBound repeats the router's wording so
// one query over the audit stream catches a hijack attempt against either kind
// of upstream.
const (
	ReasonSessionBound = "session bound to a different identity"
	ReasonSessionCap   = "session cap exceeded"
	ReasonUnauthorized = "request carries no authorized identity"
)

// Options configures a stdio Transport. Only Command is required.
type Options struct {
	// Name is the upstream's configured name, which this transport records as
	// the subject of the authorization decisions it makes itself.
	Name string
	// Command is the child executable.
	Command string
	Args    []string
	// Env entries ("KEY=VALUE") are appended to tailgate's own environment.
	Env []string
	// Dir is the child's working directory, defaulting to tailgate's.
	Dir string
	// UID and GID run the child under a different user and group than
	// tailgate's own. Zero means unset, which leaves the child at tailgate's
	// uid with no containment at all. Changing a child's uid is privileged, so
	// a tailgate that does not hold that privilege fails the spawn rather than
	// starting the child uncontained.
	UID int
	GID int
	// MaxSessions caps live sessions per identity per upstream, which is the
	// config's max_children: a session is a child. The cap is per-identity so
	// one caller cannot starve the others. It bounds one further thing that is
	// not a child: the subscription streams a single child will carry at once,
	// which cost no process but hold one open for as long as they last.
	MaxSessions int
	// IdleTimeout terminates a session no request has touched for this long.
	IdleTimeout time.Duration
	// RequestTimeout bounds the wait for a child's response to one request.
	RequestTimeout time.Duration
	// Logger receives session lifecycle and child diagnostics. It carries
	// whatever identifies the upstream, which the caller attaches once for
	// every transport it builds rather than each transport attaching its own.
	Logger *slog.Logger
	// Audit receives the authorization decisions this transport makes on its
	// own: the session bindings it owns and the per-identity cap. A nil Audit
	// still records, through the audit package's default logger.
	Audit *audit.Logger
	// KeepAliveInterval is how often a quiet subscription stream emits an SSE
	// comment. Intermediaries and client idle timeouts close a connection that
	// says nothing, and a subscription is silent whenever nothing has changed.
	KeepAliveInterval time.Duration
	// StartChild starts the child serving one session, defaulting to running
	// Command as a process under the containment the fields above configure.
	// Everything above the child is reachable through one that answers in
	// tailgate's own address space, which is what a test supplies here.
	StartChild StartChild
}

func (o Options) execConfig() execConfig {
	return execConfig{
		Command: o.Command,
		Args:    o.Args,
		Env:     o.Env,
		Dir:     o.Dir,
		UID:     o.UID,
		GID:     o.GID,
	}
}

func (o Options) withDefaults() Options {
	if o.MaxSessions <= 0 {
		o.MaxSessions = DefaultMaxSessions
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	if o.KeepAliveInterval <= 0 {
		o.KeepAliveInterval = DefaultKeepAliveInterval
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.StartChild == nil {
		o.StartChild = startExec(o.execConfig())
	}
	return o
}

// Transport serves one stdio upstream. Close must be called to stop its
// background reaper and its children.
type Transport struct {
	options Options
	logger  *slog.Logger
	audit   *audit.Logger
	drain   proxy.Drain

	reaperStopped chan struct{}
	stop          chan struct{}
	stopOnce      sync.Once

	mu     sync.Mutex
	closed bool
	// sessions holds every live child by the id that addresses it, whether a
	// caller named that id or only tailgate ever sees it.
	sessions map[string]*session
	// stateless holds the child each identity reaches when its requests carry
	// no session, which is every request under a stateless revision.
	stateless   map[string]*statelessChild
	perIdentity map[string]int
}

// New returns a Transport that spawns opts.Command per MCP session.
// Construction never spawns: a child that cannot start surfaces per-request as
// 502.
func New(opts Options) *Transport {
	opts = opts.withDefaults()
	t := &Transport{
		options:       opts,
		logger:        opts.Logger,
		audit:         opts.Audit,
		reaperStopped: make(chan struct{}),
		stop:          make(chan struct{}),
		sessions:      make(map[string]*session),
		stateless:     make(map[string]*statelessChild),
		perIdentity:   make(map[string]int),
	}
	go t.reapIdleSessions()
	return t
}

// ServeHTTP serves one MCP request against this upstream's children.
//
// POST carries every JSON-RPC message. What else is allowed depends on the
// revision the request declares: through 2025-11-25, DELETE terminates a
// session, while a stateless revision has no session to terminate and no
// standalone stream to open, so both DELETE and GET are refused with 405 as
// that revision directs.
func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	inflight, err := t.drain.Enter(r.Context())
	if err != nil {
		t.writeError(w, err)
		return
	}
	defer inflight.Done()

	identity, ok := auth.IdentityFrom(r.Context())
	if !ok || identity.Subject == "" {
		// Reaching a transport unauthenticated is a routing fault, and this
		// transport spawns processes. Fail closed rather than serve it.
		t.logger.Error("stdio transport reached without an authorized identity", "method", r.Method)
		t.audit.Deny(r.Context(), identity, t.options.Name, ReasonUnauthorized)
		t.writeError(w, errUnauthenticated)
		return
	}

	// Every session lookup below reads one copy of this header, and this
	// transport is what binds a session id to its caller, so which copy to
	// resolve is a question it must answer rather than inherit: leading with a
	// session the caller holds and trailing with one it does not would pass the
	// binding check on the value read here.
	if len(r.Header.Values(sessionHeader)) > 1 {
		t.writeError(w, errAmbiguousSession)
		return
	}

	requested := r.Header.Get(protocolVersionHeader)
	revision, err := protocol.Parse(requested)
	if err != nil {
		t.logger.Warn("stdio request declared an unsupported revision", "err", err)
		protocol.WriteUnsupportedVersion(w, requested)
		return
	}

	switch {
	case r.Method == http.MethodPost:
		t.servePost(w, r, inflight, identity, revision)
	case r.Method == http.MethodDelete && !revision.Stateless():
		t.serveDelete(w, r, identity)
	default:
		w.Header().Set("Allow", allowedMethods(revision))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// allowedMethods reports what the revision permits at the MCP endpoint.
func allowedMethods(revision protocol.Revision) string {
	if revision.Stateless() {
		return "POST"
	}
	return "POST, DELETE"
}

func (t *Transport) servePost(w http.ResponseWriter, r *http.Request, inflight *proxy.InFlight, identity auth.Identity, revision protocol.Revision) {
	body, err := t.readMessage(w, r, inflight)
	if err != nil {
		t.writeError(w, err)
		return
	}
	msg, err := parseMessage(body)
	if err != nil {
		t.writeError(w, err)
		return
	}
	if !msg.WellFormed() {
		t.writeError(w, errInvalidMessage)
		return
	}

	if revision.Stateless() {
		if !t.ownsPresentedSession(r, identity) {
			t.writeError(w, proxy.ErrSessionNotFound)
			return
		}
		t.serveStateless(w, r, inflight, identity, msg)
		return
	}

	if msg.Method == initializeMethod {
		t.serveInitialize(r.Context(), w, inflight, identity, msg)
		return
	}

	s, err := t.sessionFor(r.Context(), r.Header.Get(sessionHeader), identity)
	if err != nil {
		t.writeError(w, err)
		return
	}
	defer s.finish()

	if !msg.IsRequest() {
		// A notification is the one caller message forwarded as it arrived,
		// since it is the one carrying no id. These revisions let a server
		// open a request of its own, which is what makes a POSTed response
		// legal, but deliver drops that direction, so such a response answers
		// nothing tailgate carried. Forwarding it would put a caller-chosen id
		// into the namespace requests are minted from, where the child's
		// answer to it would satisfy another request's wait.
		if msg.IsResponse() {
			t.logger.Debug("dropping a POSTed response to a request tailgate never carried")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if err := s.send(msg.Line, t.options.RequestTimeout); err != nil {
			t.refuse(w, s, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	response, err := s.request(inflight.Context(), msg, t.options.RequestTimeout)
	if err != nil {
		t.refuse(w, s, err)
		return
	}
	writeJSON(w, response)
}

// readMessage buffers the POSTed JSON-RPC message. The read is bounded in both
// directions: maxBodyBytes caps its size, and a read deadline caps how long a
// client that stalls mid-body can hold the request in flight, which is what
// keeps such a client from stalling Shutdown and Close along with it.
func (t *Transport) readMessage(w http.ResponseWriter, r *http.Request, inflight *proxy.InFlight) ([]byte, error) {
	release := boundBodyRead(w, inflight, t.options.RequestTimeout)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		// net/http withholds the response until the unread remainder of the
		// body is drained, and it drains on Close, which a stalled client would
		// leave hanging as surely as the read itself. Closing while the expired
		// deadline still stands is what ends that drain at once, so the refusal
		// reaches the client.
		r.Body.Close()
	}
	release()
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			return nil, errBodyTooLarge
		case errors.Is(err, os.ErrDeadlineExceeded):
			return nil, errBodyTimeout
		}
		t.logger.Debug("read request body", "err", err)
		return nil, errInvalidMessage
	}
	return body, nil
}

// boundBodyRead puts a deadline on reading the request body and cancels it
// early if the request is abandoned, so Close does not wait out the deadline.
// The returned func clears the deadline and joins the watcher before the
// handler can return, since the connection is the server's again after that.
// A ResponseWriter that cannot carry a read deadline (a recorder, or a router
// that has already buffered the body) leaves the read as it found it.
func boundBodyRead(w http.ResponseWriter, inflight *proxy.InFlight, timeout time.Duration) func() {
	control := http.NewResponseController(w)
	if err := control.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return func() {}
	}

	stop := make(chan struct{})
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		select {
		case <-inflight.Context().Done():
			_ = control.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-watching
		_ = control.SetReadDeadline(time.Time{})
	}
}

// refuse answers a message the session could not carry, ending that session
// first when its child stopped reading stdin: nothing later can reach such a
// child, and leaving it registered holds the caller's cap slot until the idle
// sweep.
func (t *Transport) refuse(w http.ResponseWriter, s *session, err error) {
	if errors.Is(err, errStdinBlocked) {
		t.removeSession(s)
	}
	t.writeError(w, err)
}

// serveInitialize spawns the session's child and mints its session id. The
// router has already authorized the request, which is what keeps a spawn
// behind authentication.
func (t *Transport) serveInitialize(ctx context.Context, w http.ResponseWriter, inflight *proxy.InFlight, identity auth.Identity, msg message) {
	if !msg.IsRequest() {
		t.writeError(w, errInvalidMessage)
		return
	}

	s, err := t.newSession(identity)
	if err != nil {
		if errors.Is(err, proxy.ErrCapExceeded) {
			t.audit.Deny(ctx, identity, t.options.Name, ReasonSessionCap)
		}
		t.logger.Warn("stdio session refused", "sub", identity.Subject, "err", err)
		t.writeError(w, err)
		return
	}
	defer s.finish()

	response, err := s.request(inflight.Context(), msg, t.options.RequestTimeout)
	if err != nil {
		// A child that cannot answer initialize has no session to belong to.
		t.removeSession(s)
		t.writeError(w, err)
		return
	}

	t.logger.Info("stdio session established", "session", s.id, "sub", identity.Subject, "pid", s.child.Pid())
	w.Header().Set(sessionHeader, s.id)
	writeJSON(w, response)
}

func (t *Transport) serveDelete(w http.ResponseWriter, r *http.Request, identity auth.Identity) {
	s, err := t.sessionFor(r.Context(), r.Header.Get(sessionHeader), identity)
	if err != nil {
		t.writeError(w, err)
		return
	}
	defer s.finish()

	t.logger.Info("stdio session terminated by client", "session", s.id, "sub", identity.Subject)
	t.removeSession(s)
	w.WriteHeader(http.StatusNoContent)
}

// sessionFor resolves a session id presented by identity and claims it for the
// request, which the caller releases with finish. A session belonging to
// another identity is reported as not found, which both refuses the hijack and
// declines to confirm that the id exists.
//
// The claim is taken under the transport's lock, atomically with the lookup:
// the idle reaper decides under the same lock, so a session either is claimed
// before the sweep sees it or has already left the table, and a request that
// loses that race reports a missing session rather than a broken child.
// ownsPresentedSession reports whether a caller may proceed with whatever
// session id it presented, and records a denial when it may not.
//
// The stateless revision ignores the session header, but the binding follows
// the header rather than the declared revision: letting a caller shed the check
// by naming the revision that dropped the header would make a stdio session
// probe invisible, and this transport's own refusal is the only record of one.
// A caller presenting nothing, or its own id, proceeds.
func (t *Transport) ownsPresentedSession(r *http.Request, identity auth.Identity) bool {
	id := r.Header.Get(sessionHeader)
	if id == "" {
		return true
	}
	t.mu.Lock()
	s, ok := t.sessions[id]
	foreign := ok && s.subject != identity.Subject
	t.mu.Unlock()
	if !foreign {
		return true
	}
	t.logger.Warn("stdio session presented by another identity", "session", id, "sub", identity.Subject)
	t.audit.Deny(r.Context(), identity, t.options.Name, ReasonSessionBound)
	return false
}

func (t *Transport) sessionFor(ctx context.Context, id string, identity auth.Identity) (*session, error) {
	if id == "" {
		return nil, errMissingSessionID
	}
	t.mu.Lock()
	s, ok := t.sessions[id]
	owned := ok && s.subject == identity.Subject
	if owned {
		s.begin()
	}
	t.mu.Unlock()

	switch {
	case owned:
		return s, nil
	case ok:
		t.logger.Warn("stdio session presented by another identity", "session", id, "sub", identity.Subject)
		t.audit.Deny(ctx, identity, t.options.Name, ReasonSessionBound)
	}
	return nil, proxy.ErrSessionNotFound
}

// newSession reserves a slot against the caller's cap, spawns the child, and
// registers the session already claimed for the initialize that created it,
// which the caller releases with finish. The reservation precedes the spawn so
// a burst of concurrent initializes cannot overshoot the cap. It is released
// here only while no child exists to hold it. Once one is started, supervise
// owns the release.
func (t *Transport) newSession(identity auth.Identity) (*session, error) {
	if err := t.reserveSlot(identity.Subject); err != nil {
		return nil, err
	}

	id, err := newSessionID()
	if err != nil {
		t.releaseSlot(identity.Subject)
		return nil, err
	}
	s, err := t.spawn(id, identity.Subject)
	if err != nil {
		t.releaseSlot(identity.Subject)
		return nil, fmt.Errorf("%w: start stdio child: %v", proxy.ErrUpstreamUnavailable, err)
	}
	go t.supervise(s)

	t.mu.Lock()
	switch {
	case s.removed:
		// The child died before it was ever registered, so supervise has taken
		// it over, down to its cap slot.
		t.mu.Unlock()
		return nil, fmt.Errorf("%w: stdio child exited immediately", proxy.ErrUpstreamUnavailable)
	case t.closed:
		t.mu.Unlock()
		t.removeSession(s)
		return nil, proxy.ErrDraining
	}
	t.sessions[id] = s
	s.begin()
	t.mu.Unlock()
	return s, nil
}

func (t *Transport) reserveSlot(subject string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return proxy.ErrDraining
	}
	if t.perIdentity[subject] >= t.options.MaxSessions {
		return fmt.Errorf("%w: %d sessions", proxy.ErrCapExceeded, t.options.MaxSessions)
	}
	t.perIdentity[subject]++
	return nil
}

func (t *Transport) releaseSlot(subject string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.releaseSlotLocked(subject)
}

func (t *Transport) releaseSlotLocked(subject string) {
	if count := t.perIdentity[subject]; count > 1 {
		t.perIdentity[subject] = count - 1
	} else {
		delete(t.perIdentity, subject)
	}
}

// removeSession unregisters a session and ends its child. It is idempotent:
// client DELETE, the idle reaper, child exit, and shutdown all funnel here.
func (t *Transport) removeSession(s *session) {
	t.mu.Lock()
	t.unregisterLocked(s)
	t.mu.Unlock()

	s.terminate()
}

// unregisterLocked drops a session from the transport's tables, reporting
// whether this call is the one that removed it. The cap slot outlives it: the
// slot stands for a live child, and termination is asynchronous.
func (t *Transport) unregisterLocked(s *session) bool {
	if s.removed {
		return false
	}
	s.removed = true
	delete(t.sessions, s.id)
	// A stateless caller reaches its child by identity rather than by id, so
	// that name must go too, or the next request adopts a dead process.
	if entry, ok := t.stateless[s.subject]; ok && entry.s == s {
		delete(t.stateless, s.subject)
	}
	return true
}

// supervise reaps the child and tears its session down when it exits, so a
// server that dies on its own does not leave a session id that resolves to a
// dead process.
//
// The cap slot is released here, once the child is known to be gone. Releasing
// it at unregister instead would count registrations rather than processes, and
// a caller looping initialize and DELETE could then hold live children well
// past MaxSessions, since a terminated child has a grace period to exit in.
func (t *Transport) supervise(s *session) {
	err := s.child.Wait()
	t.releaseSlot(s.subject)
	close(s.exited)
	t.removeSession(s)
	t.logger.Info("stdio child exited", "session", s.id, "sub", s.subject, "err", err)
}

func (t *Transport) reapIdleSessions() {
	defer close(t.reaperStopped)
	ticker := time.NewTicker(reapInterval(t.options.IdleTimeout))
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case now := <-ticker.C:
			for _, s := range t.takeIdleSessions(now) {
				t.logger.Info("reaping idle stdio session", "session", s.id, "sub", s.subject)
				s.terminate()
			}
		}
	}
}

// takeIdleSessions unregisters every session no request holds and returns them
// for termination. Testing idleness and unregistering under one hold of the
// lock is what keeps the sweep from taking a session a request has just
// claimed.
func (t *Transport) takeIdleSessions(now time.Time) []*session {
	t.mu.Lock()
	defer t.mu.Unlock()
	var idle []*session
	for _, s := range t.sessions {
		if s.idleSince(now, t.options.IdleTimeout) && t.unregisterLocked(s) {
			idle = append(idle, s)
		}
	}
	return idle
}

// reapInterval keeps the sweep frequent enough that a session is reaped near
// its deadline, and rare enough that a long idle timeout does not spin.
func reapInterval(idleTimeout time.Duration) time.Duration {
	return min(max(idleTimeout/4, 10*time.Millisecond), 30*time.Second)
}

// Shutdown refuses new requests, lets in-flight exchanges finish, then
// terminates every child.
func (t *Transport) Shutdown(ctx context.Context) error {
	err := t.drain.Shutdown(ctx)
	t.stopReaper()

	sessions := t.takeSessions()
	for _, s := range sessions {
		t.removeSession(s)
	}
	if waitErr := waitForExit(ctx, sessions); waitErr != nil && err == nil {
		err = waitErr
	}
	return err
}

// Close abandons in-flight requests and kills every child immediately. It is
// safe after Shutdown.
//
// Killing the children comes first because a request blocked on a child is
// released by that child's death, so a drain waited on beforehand would be
// waiting on processes Close has yet to kill.
func (t *Transport) Close() error {
	sessions := t.takeSessions()
	for _, s := range sessions {
		t.removeSession(s)
		s.kill()
	}

	t.drain.Close()
	t.stopReaper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return waitForExit(ctx, sessions)
}

// takeSessions marks the transport closed so no further session is created,
// and returns the live ones.
func (t *Transport) takeSessions() []*session {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	sessions := make([]*session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

func (t *Transport) stopReaper() {
	t.stopOnce.Do(func() { close(t.stop) })
	<-t.reaperStopped
}

func waitForExit(ctx context.Context, sessions []*session) error {
	for _, s := range sessions {
		select {
		case <-s.exited:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// newSessionID mints a session id that is cryptographically random and visible
// ASCII, per the MCP session requirements.
func newSessionID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("%w: session id: %v", proxy.ErrUpstreamUnavailable, err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func writeJSON(w http.ResponseWriter, response []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// writeError maps a request-path failure to its status. Malformed input is the
// transport's own 400 family; everything else is the shared proxy taxonomy. A
// status other than 400 answers in status text alone: the failure detail names
// the child command, the caller's cap, and other internals an internet-facing
// response must not carry, so it goes to the log instead.
func (t *Transport) writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, context.Canceled) {
		// The caller hung up. There is nobody to answer.
		return
	}
	status := statusOf(err)
	t.logger.Warn("stdio request refused", "status", status, "err", err)
	if status == http.StatusBadRequest {
		// A 400 whose body is not a recognized JSON-RPC error is what tells a
		// client probing for the server's era that it predates the stateless
		// revision, so a refusal in bare text would talk the caller into
		// retrying with the handshake this transport no longer offers it. The
		// shape is owed to every 400, so an unnamed one still answers in it.
		message, named := badRequestMessage(err)
		if !named {
			message = http.StatusText(status)
		}
		protocol.WriteError(w, status, protocol.CodeInvalidRequest, message, nil)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// badRequestMessages is the 400 family and what each refusal says back. Every
// one names a protocol mistake in the request the caller itself wrote, so
// telling the caller which it made discloses nothing about the upstream, the
// identity, or this transport's internals. The text is written here rather
// than taken from the sentinel, whose own is prefixed with this package's name
// for the log.
var badRequestMessages = map[error]string{
	errInvalidMessage:     "invalid JSON-RPC message",
	errMissingSessionID:   "Mcp-Session-Id is required",
	errAmbiguousSession:   "Mcp-Session-Id is present more than once",
	errDuplicateRequestID: "duplicate in-flight JSON-RPC id",
}

func badRequestMessage(err error) (string, bool) {
	for sentinel, message := range badRequestMessages {
		if errors.Is(err, sentinel) {
			return message, true
		}
	}
	return "", false
}

func isBadRequest(err error) bool {
	_, named := badRequestMessage(err)
	return named
}

func statusOf(err error) int {
	switch {
	case isBadRequest(err):
		return http.StatusBadRequest
	case errors.Is(err, errBodyTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, errBodyTimeout):
		return http.StatusRequestTimeout
	case errors.Is(err, errUnauthenticated):
		return http.StatusInternalServerError
	default:
		return proxy.StatusOf(err)
	}
}

var _ proxy.Transport = (*Transport)(nil)
