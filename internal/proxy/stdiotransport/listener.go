package stdiotransport

// notificationBuffer is how many notifications a subscription stream may fall
// behind by. Beyond it the stream is closed rather than trimmed: this revision
// removed stream resumption, so a client cannot ask for what it missed, and a
// silently thinned stream is worse than one that visibly ends and can be
// reopened.
const notificationBuffer = 64

// listener is one open subscriptions/listen stream.
type listener struct {
	key int64
	// notifications carries the child's messages to the HTTP handler serving
	// the stream. Sends never block the child's reader: a full channel closes
	// the stream instead.
	notifications chan []byte
	// overflowed records that the stream ended because the reader fell behind,
	// so the handler can say so rather than report a clean close.
	overflowed bool
	closed     bool
}

// listen registers a subscription stream. The returned func unregisters it and
// must run when the HTTP handler serving the stream returns.
func (s *session) listen() (*listener, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextKey++
	l := &listener{key: s.nextKey, notifications: make(chan []byte, notificationBuffer)}
	s.listeners[l.key] = l
	return l, func() { s.unlisten(l) }
}

func (s *session) unlisten(l *listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.listeners[l.key]; !ok {
		return
	}
	delete(s.listeners, l.key)
	s.closeLocked(l)
}

// broadcast fans one notification out to every open subscription stream.
//
// It runs on the child's reader goroutine, which must never block: a stalled
// reader stops correlating every other caller's responses. A stream whose
// reader has fallen a full buffer behind is therefore closed and dropped, and
// its client reopens.
func (s *session) broadcast(line []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.listeners) == 0 {
		s.logger.Debug("dropping notification with no open subscription stream")
		return
	}
	for _, l := range s.listeners {
		if l.closed {
			continue
		}
		select {
		case l.notifications <- line:
		default:
			s.logger.Warn("subscription stream fell behind, closing it")
			l.overflowed = true
			delete(s.listeners, l.key)
			s.closeLocked(l)
		}
	}
}

// closeAllListeners ends every open subscription stream, which is what
// releases their handlers when the child goes away.
func (s *session) closeAllListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, l := range s.listeners {
		delete(s.listeners, key)
		s.closeLocked(l)
	}
}

// closeLocked closes a listener's channel once. The caller holds s.mu, which
// is also what broadcast holds, so no send can be in progress.
func (s *session) closeLocked(l *listener) {
	if l.closed {
		return
	}
	l.closed = true
	close(l.notifications)
}

// overflowedStream reports whether the stream ended because its reader fell
// behind rather than because the caller or the child ended it.
func (s *session) overflowedStream(l *listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return l.overflowed
}
