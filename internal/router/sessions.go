package router

import (
	"container/list"
	"net/http"
	"sync"
	"time"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/proxy"
)

// ReasonSessionUnrecognized is the audit reason for a session ID the router
// holds no binding for. The caller sees the same 404 as a session held by
// someone else, so the distinction lives only in the log, where a flood of
// invented session IDs and an attempt on one live session read differently.
const ReasonSessionUnrecognized = "session not recognized"

// claimSession enforces the MCP session-hijacking guidance for upstreams whose
// transport passes the upstream's own sessions through. The upstream sees only
// the header, so without this any authorized caller who learns another
// caller's session ID takes over that live session.
//
// Only an upstream minting a session ID establishes a binding, so a session the
// router never recorded is refused rather than claimed by whoever presents it
// first. A caller therefore cannot put entries in the binding table at all,
// and so cannot flood it to evict the binding guarding someone else's live
// session.
//
// The refusal is 404, matching an unknown session: it neither confirms the
// session exists nor tells the caller who owns it, and it is the status that
// makes a client discard the session and re-initialize. That is also the
// recovery path when a tailgate restart drops the table while upstream
// sessions are still live.
func (rt *Router) claimSession(rec *responseRecorder, r *http.Request, up *upstream, id auth.Identity) bool {
	if !up.bindSessions {
		return true
	}
	session := r.Header.Get(SessionHeader)
	if session == "" {
		return true
	}
	allowed, bound := rt.sessions.holds(sessionKey(up.name, session), id.Subject)
	if allowed {
		return true
	}

	reason := ReasonSessionUnrecognized
	if bound {
		reason = ReasonSessionBound
	}
	rt.audit.Deny(r.Context(), id, up.name, reason)
	http.Error(rec, "session not found", proxy.StatusOf(proxy.ErrSessionNotFound))
	return false
}

// recordSession binds a session the upstream just minted to the identity that
// initialized it, and forgets one the upstream has ended.
//
// A response outside 2xx never establishes a binding. An upstream that echoes
// the inbound session ID while rejecting the request would otherwise hand the
// rejected caller a lasting claim on a session it never issued.
func (rt *Router) recordSession(r *http.Request, up *upstream, id auth.Identity, status int, header http.Header) {
	if presented := r.Header.Get(SessionHeader); presented != "" && sessionEnded(r.Method, status) {
		rt.sessions.release(sessionKey(up.name, presented))
		return
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	if session := header.Get(SessionHeader); session != "" {
		rt.sessions.bind(sessionKey(up.name, session), id.Subject)
	}
}

// sessionEnded reports whether the upstream's answer means the session the
// caller presented is over: a successful DELETE terminated it, and a 404 says
// the upstream no longer knows it. Holding a binding past either point only
// occupies the table until its TTL.
func sessionEnded(method string, status int) bool {
	if status == http.StatusNotFound {
		return true
	}
	return method == http.MethodDelete && status >= http.StatusOK && status < http.StatusMultipleChoices
}

// sessionKey scopes a session ID to its upstream, since two upstreams mint
// session IDs independently and may collide.
func sessionKey(upstream, session string) string {
	return upstream + "\x00" + session
}

// sessionBindings maps a live session to the subject that holds it. Entries
// are bounded and expiring: the table is keyed by strings an upstream chooses,
// so it must not grow with traffic. bind is its only inserter, so eviction
// pressure comes from upstreams minting sessions and never from callers.
type sessionBindings struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	now   func() time.Time
	byKey map[string]*list.Element
	// order holds *binding with the most recently used at the front, so
	// eviction takes the session that has been quiet longest.
	order *list.List
}

type binding struct {
	key     string
	subject string
	expires time.Time
}

func newSessionBindings(max int, ttl time.Duration, now func() time.Time) *sessionBindings {
	if max <= 0 {
		max = DefaultMaxSessions
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if now == nil {
		now = time.Now
	}
	return &sessionBindings{
		max:   max,
		ttl:   ttl,
		now:   now,
		byKey: make(map[string]*list.Element),
		order: list.New(),
	}
}

// holds reports whether subject may use the session, and whether any live
// binding holds it. A miss records nothing: presenting a session ID is not a
// way to acquire one.
func (s *sessionBindings) holds(key, subject string) (allowed, bound bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	element, ok := s.live(key)
	if !ok {
		return false, false
	}
	if element.Value.(*binding).subject != subject {
		return false, true
	}
	s.touch(element)
	return true, true
}

// bind records subject as the holder of the session, replacing any binding the
// key already had. The upstream minting a session ID is authoritative about it.
func (s *sessionBindings) bind(key, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.live(key); ok {
		element.Value.(*binding).subject = subject
		s.touch(element)
		return
	}
	s.byKey[key] = s.order.PushFront(&binding{key: key, subject: subject, expires: s.now().Add(s.ttl)})
	for s.order.Len() > s.max {
		s.remove(s.order.Back())
	}
}

// release forgets a binding whose session has ended.
func (s *sessionBindings) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.byKey[key]; ok {
		s.remove(element)
	}
}

func (s *sessionBindings) live(key string) (*list.Element, bool) {
	element, ok := s.byKey[key]
	if !ok {
		return nil, false
	}
	if !s.now().Before(element.Value.(*binding).expires) {
		s.remove(element)
		return nil, false
	}
	return element, true
}

func (s *sessionBindings) touch(element *list.Element) {
	element.Value.(*binding).expires = s.now().Add(s.ttl)
	s.order.MoveToFront(element)
}

func (s *sessionBindings) remove(element *list.Element) {
	delete(s.byKey, element.Value.(*binding).key)
	s.order.Remove(element)
}
