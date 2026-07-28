package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestStatusOf(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "unknown upstream",
			err:      ErrUnknownUpstream,
			expected: http.StatusNotFound,
		},
		{
			name:     "session not found",
			err:      ErrSessionNotFound,
			expected: http.StatusNotFound,
		},
		{
			name:     "cap exceeded",
			err:      ErrCapExceeded,
			expected: http.StatusTooManyRequests,
		},
		{
			name:     "upstream unavailable",
			err:      ErrUpstreamUnavailable,
			expected: http.StatusBadGateway,
		},
		{
			name:     "upstream timeout",
			err:      ErrUpstreamTimeout,
			expected: http.StatusGatewayTimeout,
		},
		{
			name:     "draining",
			err:      ErrDraining,
			expected: http.StatusServiceUnavailable,
		},
		{
			name:     "wrapped sentinel",
			err:      fmt.Errorf("routing %q: %w", "ghost", ErrUnknownUpstream),
			expected: http.StatusNotFound,
		},
		{
			name:     "unclassified error",
			err:      errors.New("boom"),
			expected: http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusOf(tc.err); got != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, got)
			}
		})
	}
}
