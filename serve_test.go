package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

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

// fakeJoiner stands in for the embedded node. A node that cannot authenticate
// itself blocks until its context expires, which is the case the join bound
// exists for.
type fakeJoiner struct {
	fqdn  string
	err   error
	block bool
}

func (j *fakeJoiner) Up(ctx context.Context) (string, error) {
	if !j.block {
		return j.fqdn, j.err
	}
	<-ctx.Done()
	// tsnetserver.Server.Up joins the context error onto tsnet's own, which is
	// what keeps the deadline distinguishable from any other join failure.
	return "", fmt.Errorf("tsnetserver: node did not join the tailnet in time: %w",
		errors.Join(errors.New("tsnet: operation not permitted"), ctx.Err()))
}

func TestJoinTimeoutFor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     options
		expected time.Duration
	}{
		{
			name:     "unattended",
			opts:     options{},
			expected: joinTimeout,
		},
		{
			name:     "waiting on a person",
			opts:     options{OpenLoginURL: true},
			expected: interactiveJoinTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinTimeoutFor(tc.opts); got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestJoinTailnet(t *testing.T) {
	joinErr := errors.New("funnel attribute missing")

	for _, tc := range []struct {
		name string
		node *fakeJoiner
		// canceled cancels the parent context, which is the signal that asked
		// tailgate to stop.
		canceled     bool
		expectedFQDN string
		expectedIs   error
		// remedy is whether the error should tell the operator how to join,
		// which only a node that ran out of time needs to be told.
		remedy bool
	}{
		{
			name:         "join reports the node name",
			node:         &fakeJoiner{fqdn: "tailgate.example.ts.net."},
			expectedFQDN: "tailgate.example.ts.net.",
		},
		{
			name:       "a node that cannot authenticate fails closed",
			node:       &fakeJoiner{block: true},
			expectedIs: context.DeadlineExceeded,
			remedy:     true,
		},
		{
			name:       "shutdown during a join is not a failed join",
			node:       &fakeJoiner{block: true},
			canceled:   true,
			expectedIs: context.Canceled,
		},
		{
			name:       "any other join failure passes through",
			node:       &fakeJoiner{err: joinErr},
			expectedIs: joinErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}

			fqdn, err := joinTailnet(ctx, tc.node, 10*time.Millisecond)

			if fqdn != tc.expectedFQDN {
				t.Errorf("expected fqdn %q, got %q", tc.expectedFQDN, fqdn)
			}
			if tc.expectedIs == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.expectedIs) {
				t.Fatalf("expected error matching %v, got %v", tc.expectedIs, err)
			}
			for _, remedy := range []string{"TS_AUTHKEY", "-open-login"} {
				if strings.Contains(err.Error(), remedy) != tc.remedy {
					t.Errorf("expected mention of %s to be %t in %v", remedy, tc.remedy, err)
				}
			}
		})
	}
}
