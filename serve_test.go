package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// recorder captures the order of the shutdown steps, which is the whole
// contract: accepting must stop before anything drains, or a connection
// arriving mid-drain reaches a transport that is already refusing work.
type recorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *recorder) record(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

func (r *recorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.steps...)
}

type fakeStopper struct {
	steps *recorder
	err   error
}

func (s *fakeStopper) StopAccepting() error {
	s.steps.record("stop")
	return s.err
}

type fakeTransports struct {
	steps *recorder
	err   error
}

func (t *fakeTransports) Shutdown(context.Context) error {
	t.steps.record("drain")
	return t.err
}

func TestDrain(t *testing.T) {
	stopErr := errors.New("listener already closed")
	drainErr := errors.New("upstream still busy")

	for _, tc := range []struct {
		name     string
		stopErr  error
		drainErr error
		expected []error
	}{
		{
			name: "clean",
		},
		{
			name:     "listener stop fails",
			stopErr:  stopErr,
			expected: []error{stopErr},
		},
		{
			name:     "upstreams do not drain",
			drainErr: drainErr,
			expected: []error{drainErr},
		},
		{
			name:     "both fail",
			stopErr:  stopErr,
			drainErr: drainErr,
			expected: []error{stopErr, drainErr},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps := &recorder{}
			err := drain(
				discardLogger(),
				&fakeStopper{steps: steps, err: tc.stopErr},
				&http.Server{},
				&fakeTransports{steps: steps, err: tc.drainErr},
			)

			if diff := cmp.Diff([]string{"stop", "drain"}, steps.recorded()); diff != "" {
				t.Errorf("shutdown steps differ:\n%s", diff)
			}
			for _, expected := range tc.expected {
				if !errors.Is(err, expected) {
					t.Errorf("expected %v in %v", expected, err)
				}
			}
			if len(tc.expected) == 0 && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
