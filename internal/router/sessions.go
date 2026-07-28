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
// first. A caller cannot choose a key in the table, and eviction is charged to
// the subject holding the most bindings, so looping initialize costs the caller
// its own sessions rather than the ones guarding other callers' live sessions.
//
// The refusal is 404, matching an unknown session: it neither confirms the
// session exists nor tells the caller who owns it, and it is the status that
// makes a client discard the session and re-initialize. That is also the
// recovery path when a tailgate restart drops the table while upstream
// sessions are still live.
//
// A claim retains the binding for the life of the request, so the returned
// release must run once the response is done.
func (rt *Router) claimSession(rec *responseRecorder, r *http.Request, up *upstream, id auth.Identity) (release func(), ok bool) {
	if !up.bindSessions {
		return func() {}, true
	}
	session := r.Header.Get(SessionHeader)
	if session == "" {
		return func() {}, true
	}
	key := sessionKey(up.name, session)
	allowed, bound := rt.sessions.holds(key, id.Subject)
	if allowed {
		return func() { rt.sessions.releaseHold(key) }, true
	}

	reason := ReasonSessionUnrecognized
	if bound {
		reason = ReasonSessionBound
	}
	rt.audit.Deny(r.Context(), id, up.name, reason)
	http.Error(rec, "session not found", proxy.StatusOf(proxy.ErrSessionNotFound))
	return nil, false
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
// so it must not grow with traffic. bind is its only inserter, but a caller
// drives insertion indirectly by asking an upstream to initialize, so the
// bound is enforced per subject rather than globally.
type sessionBindings struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	now  func() time.Time
	size int

	byKey map[string]*list.Element
	// bySubject holds each subject's bindings with the most recently used at
	// the front. Eviction takes from whichever subject holds the most, so a
	// caller minting sessions in a loop pushes out its own bindings instead of
	// the ones guarding another caller's live session.
	bySubject map[string]*list.List
}

type binding struct {
	key     string
	subject string
	expires time.Time
	// holds counts the requests currently using the session. A held binding
	// never expires, so a stream that outlives the TTL without traffic to
	// refresh it does not lose its binding mid-response.
	holds int
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
		max:       max,
		ttl:       ttl,
		now:       now,
		byKey:     make(map[string]*list.Element),
		bySubject: make(map[string]*list.List),
	}
}

// holds reports whether subject may use the session, and whether any live
// binding holds it. A miss records nothing: presenting a session ID is not a
// way to acquire one. An allowed session is retained until releaseHold runs.
func (s *sessionBindings) holds(key, subject string) (allowed, bound bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	element, ok := s.live(key)
	if !ok {
		return false, false
	}
	held := element.Value.(*binding)
	if held.subject != subject {
		return false, true
	}
	held.holds++
	s.touch(element)
	return true, true
}

// releaseHold ends the retention holds took, dating the binding's expiry from
// when the request finished rather than when it started.
func (s *sessionBindings) releaseHold(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	element, ok := s.byKey[key]
	if !ok {
		return
	}
	held := element.Value.(*binding)
	if held.holds > 0 {
		held.holds--
	}
	held.expires = s.now().Add(s.ttl)
}

// bind records subject as the holder of the session, replacing any binding the
// key already had. The upstream minting a session ID is authoritative about it.
func (s *sessionBindings) bind(key, subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.live(key); ok {
		if held := element.Value.(*binding); held.subject == subject {
			s.touch(element)
			return
		}
		s.remove(element)
	}

	sessions, ok := s.bySubject[subject]
	if !ok {
		sessions = list.New()
		s.bySubject[subject] = sessions
	}
	s.byKey[key] = sessions.PushFront(&binding{key: key, subject: subject, expires: s.now().Add(s.ttl)})
	s.size++
	for s.size > s.max {
		if !s.evict() {
			return
		}
	}
}

// evict drops the least recently used unheld binding of the subject holding the
// most, and reports whether it found one. Charging eviction to the widest
// holder is what keeps one caller's session churn off every other caller.
func (s *sessionBindings) evict() bool {
	var widest *list.List
	for _, sessions := range s.bySubject {
		if widest == nil || sessions.Len() > widest.Len() {
			widest = sessions
		}
	}
	if widest == nil {
		return false
	}
	for element := widest.Back(); element != nil; element = element.Prev() {
		if element.Value.(*binding).holds == 0 {
			s.remove(element)
			return true
		}
	}
	return false
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
	held := element.Value.(*binding)
	if held.holds == 0 && !s.now().Before(held.expires) {
		s.remove(element)
		return nil, false
	}
	return element, true
}

func (s *sessionBindings) touch(element *list.Element) {
	held := element.Value.(*binding)
	held.expires = s.now().Add(s.ttl)
	if sessions, ok := s.bySubject[held.subject]; ok {
		sessions.MoveToFront(element)
	}
}

func (s *sessionBindings) remove(element *list.Element) {
	held := element.Value.(*binding)
	delete(s.byKey, held.key)
	if sessions, ok := s.bySubject[held.subject]; ok {
		sessions.Remove(element)
		if sessions.Len() == 0 {
			delete(s.bySubject, held.subject)
		}
	}
	s.size--
}
