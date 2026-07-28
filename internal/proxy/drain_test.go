package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDrainEnter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		begin    func(d *Drain)
		expected error
	}{
		{
			name:     "fresh drain admits",
			begin:    func(*Drain) {},
			expected: nil,
		},
		{
			name: "after shutdown refuses",
			begin: func(d *Drain) {
				if err := d.Shutdown(context.Background()); err != nil {
					t.Fatalf("shutdown: %v", err)
				}
			},
			expected: ErrDraining,
		},
		{
			name:     "after close refuses",
			begin:    func(d *Drain) { d.Close() },
			expected: ErrDraining,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d Drain
			tc.begin(&d)
			inflight, err := d.Enter(t.Context())
			if !errors.Is(err, tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, err)
			}
			if err == nil {
				inflight.Done()
			}
		})
	}
}

func TestDrainShutdownWaitsForInFlight(t *testing.T) {
	var d Drain
	inflight, err := d.Enter(t.Context())
	if err != nil {
		t.Fatalf("enter: %v", err)
	}

	expired, cancel := context.WithCancel(t.Context())
	cancel()
	if err := d.Shutdown(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled while a request is in flight, got %v", err)
	}

	inflight.Done()
	if err := d.Shutdown(t.Context()); err != nil {
		t.Fatalf("expected a clean drain once the request released, got %v", err)
	}
}

func TestDrainCloseCancelsInFlight(t *testing.T) {
	var d Drain
	inflight, err := d.Enter(t.Context())
	if err != nil {
		t.Fatalf("enter: %v", err)
	}

	closed := make(chan struct{})
	go func() {
		d.Close()
		close(closed)
	}()

	select {
	case <-inflight.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Close never canceled the in-flight request")
	}
	if cause := context.Cause(inflight.Context()); !errors.Is(cause, ErrDraining) {
		t.Errorf("expected cause ErrDraining, got %v", cause)
	}

	select {
	case <-closed:
		t.Fatal("Close returned before the request released")
	case <-time.After(50 * time.Millisecond):
	}

	inflight.Done()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the request released")
	}
}

func TestInFlightCancelCause(t *testing.T) {
	var d Drain
	inflight, err := d.Enter(t.Context())
	if err != nil {
		t.Fatalf("enter: %v", err)
	}
	defer inflight.Done()

	inflight.Cancel(ErrUpstreamTimeout)
	if cause := context.Cause(inflight.Context()); !errors.Is(cause, ErrUpstreamTimeout) {
		t.Fatalf("expected cause ErrUpstreamTimeout, got %v", cause)
	}
}

func TestInFlightDoneIsIdempotent(t *testing.T) {
	var d Drain
	inflight, err := d.Enter(t.Context())
	if err != nil {
		t.Fatalf("enter: %v", err)
	}
	inflight.Done()
	// A second Done would panic on a negative WaitGroup counter if it were not
	// guarded, which is what a handler with both a defer and an early release
	// would do.
	inflight.Done()

	if err := d.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
