// Package audit records tailgate's authorization decisions as structured logs.
//
// Every allow and deny is emitted with the same message and the same attribute
// keys, so a decision is queryable by outcome, caller, and upstream without
// parsing free text. The package holds no policy: it reports the decision it is
// given.
package audit

import (
	"context"
	"log/slog"

	"github.com/bendrucker/tailgate/internal/auth"
)

// Message is the log message every decision record carries.
const Message = "authorization decision"

// Attribute keys on a decision record. Every record sets all of them, including
// empty values, so a consumer never has to distinguish an absent key from an
// unknown claim.
const (
	KeyOutcome  = "outcome"
	KeySubject  = "sub"
	KeyEmail    = "email"
	KeyUpstream = "upstream"
	KeyReason   = "reason"
	// KeyRule names the policy rule that allowed the request, by its position
	// in the configured policy. It is empty on a denial, where no rule matched.
	KeyRule = "rule"
)

// Outcome values for KeyOutcome.
const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
)

// Logger writes authorization decisions to a slog handler.
type Logger struct {
	log *slog.Logger
}

// New returns a Logger writing to log, defaulting to slog.Default when log is
// nil.
func New(log *slog.Logger) *Logger {
	return &Logger{log: log}
}

// Record emits d. Denials log at warn and allows at info: a denial is the
// security-relevant event, and an operator filtering to warn still sees every
// rejected caller.
func (l *Logger) Record(ctx context.Context, d auth.Decision) {
	outcome, level := OutcomeDeny, slog.LevelWarn
	if d.Allow {
		outcome, level = OutcomeAllow, slog.LevelInfo
	}
	// Identity.Claims is deliberately not logged: it is the raw introspection
	// response, which carries scope and profile claims tailgate has no reason
	// to retain in an audit record.
	l.logger().LogAttrs(ctx, level, Message,
		slog.String(KeyOutcome, outcome),
		slog.String(KeySubject, d.Identity.Subject),
		slog.String(KeyEmail, d.Identity.Email),
		slog.String(KeyUpstream, d.Upstream),
		slog.String(KeyReason, d.Reason),
		slog.String(KeyRule, d.Rule),
	)
}

// Allow records an authorized request for upstream. reason identifies what
// permitted it, such as the matched policy rule.
func (l *Logger) Allow(ctx context.Context, id auth.Identity, upstream, reason string) {
	l.Record(ctx, auth.Decision{Identity: id, Upstream: upstream, Allow: true, Reason: reason})
}

// Deny records a refused request for upstream. reason identifies what refused
// it, such as a sentinel error from verification. id may be zero when the
// request was denied before an identity was established.
func (l *Logger) Deny(ctx context.Context, id auth.Identity, upstream, reason string) {
	l.Record(ctx, auth.Decision{Identity: id, Upstream: upstream, Allow: false, Reason: reason})
}

// logger tolerates a nil Logger so an unwired audit dependency cannot panic in
// the request path or silence a decision.
func (l *Logger) logger() *slog.Logger {
	if l == nil || l.log == nil {
		return slog.Default()
	}
	return l.log
}
