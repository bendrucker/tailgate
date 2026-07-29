package protocol

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		value    string
		expected Revision
		err      error
	}{
		{
			name:     "empty assumes the revision that predates the header",
			value:    "",
			expected: Assumed,
		},
		{
			name:     "stateful revision",
			value:    "2025-11-25",
			expected: Rev20251125,
		},
		{
			name:     "stateless revision",
			value:    "2026-07-28",
			expected: Rev20260728,
		},
		{
			name:  "unknown revision",
			value: "2027-01-01",
			err:   ErrUnsupportedRevision,
		},
		{
			name:  "not a revision at all",
			value: "latest",
			err:   ErrUnsupportedRevision,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revision, err := Parse(tc.value)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected error %v, got %v", tc.err, err)
			}
			if revision != tc.expected {
				t.Errorf("expected revision %q, got %q", tc.expected, revision)
			}
		})
	}
}

func TestRevisionEras(t *testing.T) {
	for _, tc := range []struct {
		name      string
		revision  Revision
		stateless bool
		mirrors   bool
	}{
		{name: "first revision predates the session header", revision: Rev20241105},
		{name: "streamable http arrives stateful", revision: Rev20250326},
		{name: "version header arrives stateful", revision: Rev20250618},
		{name: "last stateful revision", revision: Rev20251125},
		{name: "sessions and handshake removed", revision: Rev20260728, stateless: true, mirrors: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.revision.Stateless(); got != tc.stateless {
				t.Errorf("expected Stateless %v, got %v", tc.stateless, got)
			}
			if got := tc.revision.MirrorsHeaders(); got != tc.mirrors {
				t.Errorf("expected MirrorsHeaders %v, got %v", tc.mirrors, got)
			}
		})
	}
}
