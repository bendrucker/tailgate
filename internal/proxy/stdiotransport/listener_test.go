package stdiotransport

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// TestListenCapsStreamsPerChild covers the bound a subscription needs of its
// own. A stream costs no process, so the child cap does not reach it, but it is
// exempt from the exchange timeout and holds its child off the idle sweep for
// as long as it stays open.
func TestListenCapsStreamsPerChild(t *testing.T) {
	const capacity = 3
	s := newTestSession()

	var releases []func()
	for i := range capacity {
		_, release, err := s.listen(capacity)
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		releases = append(releases, release)
	}

	if _, _, err := s.listen(capacity); !errors.Is(err, proxy.ErrCapExceeded) {
		t.Fatalf("expected the cap to hold, got %v", err)
	}

	// A handler that returns frees its slot, or a client that opens and hangs up
	// in a loop reaches the cap permanently without holding a single live
	// stream.
	releases[0]()
	if _, _, err := s.listen(capacity); err != nil {
		t.Fatalf("expected a released slot to be reusable, got %v", err)
	}

	// Releasing twice is what a handler that already lost its stream to the
	// child's exit does.
	releases[0]()
}

// TestBroadcastDropsOnlyTheStreamThatFellBehind covers the one place a
// notification is lost on purpose. Broadcast runs on the child's reader, which
// must never block: a stalled reader stops correlating every other caller's
// responses. A stream a full buffer behind is therefore closed and dropped, and
// its client reopens, since this revision removed stream resumption and a
// silently thinned stream is worse than one that visibly ends.
func TestBroadcastDropsOnlyTheStreamThatFellBehind(t *testing.T) {
	notification := func(seq int) []byte {
		return fmt.Appendf(nil, `{"jsonrpc":"2.0","method":"notifications/message","params":{"seq":%d}}`, seq)
	}

	s := newTestSession()
	stalled, _, err := s.listen(4)
	if err != nil {
		t.Fatalf("open the stalled stream: %v", err)
	}
	for seq := range notificationBuffer {
		s.broadcast(notification(seq))
	}
	if s.overflowedStream(stalled) {
		t.Fatal("a stream was dropped inside its buffer")
	}

	// Registered after the first stream filled, so it is empty when the
	// notification that overflows the other arrives.
	keeping, _, err := s.listen(4)
	if err != nil {
		t.Fatalf("open the second stream: %v", err)
	}
	s.broadcast(notification(notificationBuffer))

	if !s.overflowedStream(stalled) {
		t.Error("the stalled stream was not recorded as having fallen behind")
	}
	// Its handler is released, and what it did buffer is still readable in the
	// order the child emitted it.
	delivered := 0
	for line := range stalled.notifications {
		if want := string(notification(delivered)); string(line) != want {
			t.Fatalf("notification %d = %s, want %s", delivered, line, want)
		}
		delivered++
	}
	if delivered != notificationBuffer {
		t.Errorf("the dropped stream held %d notifications, want %d", delivered, notificationBuffer)
	}

	select {
	case line := <-keeping.notifications:
		if want := string(notification(notificationBuffer)); string(line) != want {
			t.Errorf("the second stream got %s, want %s", line, want)
		}
	default:
		t.Error("the notification never reached the stream that was keeping up")
	}

	if count := s.listenerCount(); count != 1 {
		t.Errorf("expected the dropped stream to be unregistered, got %d registered", count)
	}
}

// TestCloseAllListenersReleasesEveryHandler covers what the child's output
// ending does to the streams it was the only source for: their handlers are
// released here.
func TestCloseAllListenersReleasesEveryHandler(t *testing.T) {
	s := newTestSession()
	var streams []*listener
	for range 3 {
		l, _, err := s.listen(4)
		if err != nil {
			t.Fatalf("open a stream: %v", err)
		}
		streams = append(streams, l)
	}

	s.closeAllListeners()

	for i, l := range streams {
		if _, open := <-l.notifications; open {
			t.Errorf("stream %d was left open", i)
		}
		if s.overflowedStream(l) {
			t.Errorf("stream %d was reported as having fallen behind", i)
		}
	}
	if count := s.listenerCount(); count != 0 {
		t.Errorf("expected every stream unregistered, got %d", count)
	}

	// A broadcast arriving after the child's output ended reaches nothing,
	// rather than sending on a closed channel.
	s.broadcast([]byte(`{"jsonrpc":"2.0","method":"notifications/message"}`))
}

func (s *session) listenerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.listeners)
}
