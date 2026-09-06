package stdiotransport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// collectMessages runs scanMessages over r and returns everything it framed
// along with the error that ended the stream.
func collectMessages(t *testing.T, r io.Reader) ([]string, error) {
	t.Helper()
	out := make(chan []byte)
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(out)
		err = scanMessages(r, out)
	}()

	var lines []string
	for line := range out {
		lines = append(lines, string(line))
	}
	<-done
	return lines, err
}

func TestScanMessages(t *testing.T) {
	// One token past the framing limit, which is what a child emitting an
	// unbounded result leaves on the pipe.
	oversized := strings.Repeat("x", maxLineBytes+1)

	for _, tc := range []struct {
		name     string
		output   string
		expected []string
		err      error
	}{
		{
			name:     "each line is one message",
			output:   "{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n",
			expected: []string{`{"id":1}`, `{"id":2}`, `{"id":3}`},
		},
		{
			// A child that exits without a trailing newline has still said
			// something whole.
			name:     "a final line without a newline is a message",
			output:   "{\"id\":1}\n{\"id\":2}",
			expected: []string{`{"id":1}`, `{"id":2}`},
		},
		{
			name:   "no output frames nothing",
			output: "",
		},
		{
			// Nothing after the oversized line can be trusted to be a whole
			// message, so the stream ends where the framing did.
			name:   "output past the framing limit ends the stream",
			output: oversized + "\n{\"id\":1}\n",
			err:    bufio.ErrTooLong,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines, err := collectMessages(t, strings.NewReader(tc.output))
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected %v, got %v", tc.err, err)
			}
			if len(lines) != len(tc.expected) {
				t.Fatalf("expected %d messages, got %d: %q", len(tc.expected), len(lines), lines)
			}
			for i, line := range lines {
				if line != tc.expected[i] {
					t.Errorf("message %d = %q, want %q", i, line, tc.expected[i])
				}
			}
		})
	}
}

// TestLogLinesDrainsPastTheFramingLimit covers the child that floods its
// stderr. Nothing further can be framed as a line, but the child goes on
// writing, and a pipe no one reads stops it on its next write with the session
// otherwise healthy. Reading the rest away costs the diagnostics and keeps the
// child running.
func TestLogLinesDrainsPastTheFramingLimit(t *testing.T) {
	stderr := strings.NewReader(strings.Repeat("x", maxLineBytes+1) + "\nand more\n")
	logs := &syncBuffer{}

	logLines(stderr, slog.New(slog.NewJSONHandler(logs, nil)))

	if stderr.Len() != 0 {
		t.Errorf("logLines left %d bytes for the child to block on", stderr.Len())
	}
	if !strings.Contains(logs.String(), "stdio child stderr ended in error") {
		t.Errorf("expected the framing failure to be logged, got %q", logs.String())
	}
}

// TestExecConfigEnviron covers what a child inherits. The scrub removes the one
// long-lived transportable credential tailgate holds and nothing else, and the
// upstream's own entries land last, which is both how an operator adds one and
// how they override an inherited one.
func TestExecConfigEnviron(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "tskey-parent")
	t.Setenv("TS_AUTH_KEY", "tskey-parent")
	t.Setenv("TAILGATE_TEST_HOME", "/parent")

	for _, tc := range []struct {
		name     string
		env      []string
		expected map[string]string
		absent   []string
	}{
		{
			name:     "the tailnet auth key is scrubbed under both spellings",
			expected: map[string]string{"TAILGATE_TEST_HOME": "/parent"},
			absent:   []string{"TS_AUTHKEY", "TS_AUTH_KEY"},
		},
		{
			name:     "the upstream's own entries are added",
			env:      []string{"TAILGATE_TEST_TOKEN=upstream"},
			expected: map[string]string{"TAILGATE_TEST_TOKEN": "upstream", "TAILGATE_TEST_HOME": "/parent"},
		},
		{
			// A child running under its own uid names its own HOME here,
			// since it cannot write tailgate's.
			name:     "an upstream entry overrides the inherited one",
			env:      []string{"TAILGATE_TEST_HOME=/child"},
			expected: map[string]string{"TAILGATE_TEST_HOME": "/child"},
		},
		{
			// The scrub is not a boundary: an operator naming the key is
			// deliberately handing the child a value.
			name:     "an upstream may name the auth key itself",
			env:      []string{"TS_AUTHKEY=tskey-upstream"},
			expected: map[string]string{"TS_AUTHKEY": "tskey-upstream"},
			absent:   []string{"TS_AUTH_KEY"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := execConfig{Env: tc.env}.environ()
			for name, expected := range tc.expected {
				value, ok := lastValue(env, name)
				if !ok {
					t.Errorf("%s is absent from the child's environment", name)
					continue
				}
				if value != expected {
					t.Errorf("%s = %q, want %q", name, value, expected)
				}
			}
			for _, name := range tc.absent {
				if value, ok := lastValue(env, name); ok {
					t.Errorf("%s reached the child as %q", name, value)
				}
			}
		})
	}
}

// lastValue reads a name out of an environment the way os/exec does, keeping
// the last occurrence.
func lastValue(env []string, name string) (string, bool) {
	value, found := "", false
	for _, entry := range env {
		if key, rest, ok := strings.Cut(entry, "="); ok && key == name {
			value, found = rest, true
		}
	}
	return value, found
}

// TestExecConfigStartError covers the cause a configured uid makes likely and
// the error text does not. An upstream configured for containment that tailgate
// cannot start is unavailable, and an operator reading the log needs the reason
// named.
func TestExecConfigStartError(t *testing.T) {
	failure := fmt.Errorf("fork/exec: operation not permitted")

	for _, tc := range []struct {
		name     string
		cfg      execConfig
		contains []string
	}{
		{
			name: "an uncontained child reports the error itself",
			cfg:  execConfig{},
		},
		{
			name:     "a contained child names the privilege it needed",
			cfg:      execConfig{UID: 1, GID: 2},
			contains: []string{"uid 1 gid 2", "privilege"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.startError(failure)
			if !errors.Is(err, failure) {
				t.Fatalf("the underlying failure was lost: %v", err)
			}
			for _, text := range tc.contains {
				if !strings.Contains(err.Error(), text) {
					t.Errorf("error = %q, want it to name %q", err, text)
				}
			}
			if len(tc.contains) == 0 && err != failure {
				t.Errorf("error = %q, want the failure unchanged", err)
			}
		})
	}
}

// TestExecConfigGrace covers the default a zero Grace takes, since an upstream
// configured without one must still bound how long a child that ignores its
// stdin closing goes on running.
func TestExecConfigGrace(t *testing.T) {
	if grace := (execConfig{}).grace(); grace != DefaultShutdownGrace {
		t.Errorf("grace = %v, want %v", grace, DefaultShutdownGrace)
	}
	if grace := (execConfig{Grace: 1}).grace(); grace != 1 {
		t.Errorf("grace = %v, want the configured 1ns", grace)
	}
}
