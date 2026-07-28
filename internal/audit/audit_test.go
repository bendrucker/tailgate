package audit

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/google/go-cmp/cmp"
)

type entry struct {
	Level slog.Level
	Msg   string
	Attrs map[string]any
	Tag   any
}

// recorder captures records as plain data, including a context value, so tests
// assert the exact attribute set and that the caller's context reaches the
// handler.
type recorder struct {
	entries []entry
}

type tagKey struct{}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(ctx context.Context, rec slog.Record) error {
	e := entry{Level: rec.Level, Msg: rec.Message, Attrs: map[string]any{}, Tag: ctx.Value(tagKey{})}
	rec.Attrs(func(a slog.Attr) bool {
		e.Attrs[a.Key] = a.Value.Any()
		return true
	})
	r.entries = append(r.entries, e)
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *recorder) WithGroup(string) slog.Handler { return r }

func TestRecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision auth.Decision
		expected entry
	}{
		{
			name: "allow with matched rule",
			decision: auth.Decision{
				Identity: auth.Identity{
					Subject: "12345",
					Email:   "user@example.com",
					Claims:  map[string]any{"scope": "openid email", "username": "user"},
				},
				Upstream: "files",
				Allow:    true,
				Reason:   "policy: email allowlist",
				Rule:     "policy[0].allow[1]",
			},
			expected: entry{
				Level: slog.LevelInfo,
				Msg:   Message,
				Attrs: map[string]any{
					KeyOutcome:  OutcomeAllow,
					KeySubject:  "12345",
					KeyEmail:    "user@example.com",
					KeyUpstream: "files",
					KeyReason:   "policy: email allowlist",
					KeyRule:     "policy[0].allow[1]",
				},
			},
		},
		{
			name: "deny with identity",
			decision: auth.Decision{
				Identity: auth.Identity{Subject: "67890", Email: "other@example.com"},
				Upstream: "files",
				Allow:    false,
				Reason:   "policy: no matching rule",
			},
			expected: entry{
				Level: slog.LevelWarn,
				Msg:   Message,
				Attrs: map[string]any{
					KeyOutcome:  OutcomeDeny,
					KeySubject:  "67890",
					KeyEmail:    "other@example.com",
					KeyUpstream: "files",
					KeyReason:   "policy: no matching rule",
					KeyRule:     "",
				},
			},
		},
		{
			name: "deny before identity is established",
			decision: auth.Decision{
				Upstream: "files",
				Allow:    false,
				Reason:   auth.ErrInvalidToken.Error(),
			},
			expected: entry{
				Level: slog.LevelWarn,
				Msg:   Message,
				Attrs: map[string]any{
					KeyOutcome:  OutcomeDeny,
					KeySubject:  "",
					KeyEmail:    "",
					KeyUpstream: "files",
					KeyReason:   "auth: invalid token",
					KeyRule:     "",
				},
			},
		},
		{
			name: "allow without email scope",
			decision: auth.Decision{
				Identity: auth.Identity{Subject: "12345"},
				Upstream: "notes",
				Allow:    true,
				Reason:   "policy: sub allowlist",
			},
			expected: entry{
				Level: slog.LevelInfo,
				Msg:   Message,
				Attrs: map[string]any{
					KeyOutcome:  OutcomeAllow,
					KeySubject:  "12345",
					KeyEmail:    "",
					KeyUpstream: "notes",
					KeyReason:   "policy: sub allowlist",
					KeyRule:     "",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			New(slog.New(rec)).Record(context.Background(), tc.decision)

			if len(rec.entries) != 1 {
				t.Fatalf("expected 1 record, got %d", len(rec.entries))
			}
			if diff := cmp.Diff(tc.expected, rec.entries[0]); diff != "" {
				t.Errorf("record mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOutcomeHelpers(t *testing.T) {
	identity := auth.Identity{Subject: "12345", Email: "user@example.com"}

	for _, tc := range []struct {
		name     string
		record   func(*Logger, context.Context)
		expected entry
	}{
		{
			name: "allow",
			record: func(l *Logger, ctx context.Context) {
				l.Allow(ctx, identity, "files", "policy: email allowlist")
			},
			expected: entry{
				Level: slog.LevelInfo,
				Msg:   Message,
				Attrs: map[string]any{
					KeyOutcome:  OutcomeAllow,
					KeySubject:  "12345",
					KeyEmail:    "user@example.com",
					KeyUpstream: "files",
					KeyReason:   "policy: email allowlist",
					KeyRule:     "",
				},
			},
		},
		{
			name: "deny",
			record: func(l *Logger, ctx context.Context) {
				l.Deny(ctx, identity, "files", "policy: no matching rule")
			},
			expected: entry{
				Level: slog.LevelWarn,
				Msg:   Message,
				Attrs: map[string]any{
					KeyOutcome:  OutcomeDeny,
					KeySubject:  "12345",
					KeyEmail:    "user@example.com",
					KeyUpstream: "files",
					KeyReason:   "policy: no matching rule",
					KeyRule:     "",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			tc.record(New(slog.New(rec)), context.Background())

			if len(rec.entries) != 1 {
				t.Fatalf("expected 1 record, got %d", len(rec.entries))
			}
			if diff := cmp.Diff(tc.expected, rec.entries[0]); diff != "" {
				t.Errorf("record mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRecordPassesContext(t *testing.T) {
	rec := &recorder{}
	ctx := context.WithValue(context.Background(), tagKey{}, "request-scoped")

	New(slog.New(rec)).Deny(ctx, auth.Identity{}, "files", "policy: no matching rule")

	if len(rec.entries) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rec.entries))
	}
	if got := rec.entries[0].Tag; got != "request-scoped" {
		t.Errorf("expected handler to see the caller's context value, got %v", got)
	}
}

func TestRecordFallsBackToDefaultLogger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		logger *Logger
	}{
		{name: "nil logger", logger: nil},
		{name: "nil slog logger", logger: New(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			restore := slog.Default()
			slog.SetDefault(slog.New(rec))
			t.Cleanup(func() { slog.SetDefault(restore) })

			tc.logger.Deny(context.Background(), auth.Identity{Subject: "12345"}, "files", "policy: no matching rule")

			if len(rec.entries) != 1 {
				t.Fatalf("expected 1 record, got %d", len(rec.entries))
			}
			if got := rec.entries[0].Attrs[KeyOutcome]; got != OutcomeDeny {
				t.Errorf("expected outcome %q, got %v", OutcomeDeny, got)
			}
		})
	}
}
