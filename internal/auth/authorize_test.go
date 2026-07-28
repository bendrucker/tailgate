package auth

import (
	"testing"

	"github.com/bendrucker/tailgate/internal/config"
	"github.com/google/go-cmp/cmp"
)

// testPolicy exercises every shape the shipped config supports: a sub
// allowlist, an email allowlist, a rule joining both, and a claim match.
func testPolicy() []config.Rule {
	return []config.Rule{
		{
			Upstream: "github",
			Allow: []config.Match{
				{Subject: "12345"},
				{Email: "bvdrucker@gmail.com"},
				{Subject: "777", Email: "ops@example.com"},
				{Claim: map[string]string{"username": "svc@github"}},
			},
		},
		{
			Upstream: "linear",
			Allow:    []config.Match{{Subject: "999"}},
		},
	}
}

func TestAuthorize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity Identity
		upstream string
		allow    bool
		rule     string
		reason   string
	}{
		{
			name:     "sub allowlist admits the subject",
			identity: Identity{Subject: "12345"},
			upstream: "github",
			allow:    true,
			rule:     "policy[0].allow[0]",
			reason:   ReasonMatched,
		},
		{
			name:     "email allowlist admits the address",
			identity: Identity{Subject: "54321", Email: "bvdrucker@gmail.com"},
			upstream: "github",
			allow:    true,
			rule:     "policy[0].allow[1]",
			reason:   ReasonMatched,
		},
		{
			name:     "token without the email scope denies an email rule",
			identity: Identity{Subject: "54321"},
			upstream: "github",
			reason:   ReasonNoMatch,
		},
		{
			name:     "unlisted identity denies",
			identity: Identity{Subject: "54321", Email: "stranger@example.com"},
			upstream: "github",
			reason:   ReasonNoMatch,
		},
		{
			name:     "rule with two conditions needs both",
			identity: Identity{Subject: "777"},
			upstream: "github",
			reason:   ReasonNoMatch,
		},
		{
			name:     "rule with two conditions admits when both hold",
			identity: Identity{Subject: "777", Email: "ops@example.com"},
			upstream: "github",
			allow:    true,
			rule:     "policy[0].allow[2]",
			reason:   ReasonMatched,
		},
		{
			name:     "claim match admits",
			identity: Identity{Subject: "31337", Claims: map[string]any{"username": "svc@github"}},
			upstream: "github",
			allow:    true,
			rule:     "policy[0].allow[3]",
			reason:   ReasonMatched,
		},
		{
			name:     "claim match denies a non string claim",
			identity: Identity{Subject: "31337", Claims: map[string]any{"username": float64(42)}},
			upstream: "github",
			reason:   ReasonNoMatch,
		},
		{
			name:     "policy is scoped to one upstream",
			identity: Identity{Subject: "999"},
			upstream: "github",
			reason:   ReasonNoMatch,
		},
		{
			name:     "second rule admits its own upstream",
			identity: Identity{Subject: "999"},
			upstream: "linear",
			allow:    true,
			rule:     "policy[1].allow[0]",
			reason:   ReasonMatched,
		},
		{
			name:     "upstream with no policy denies",
			identity: Identity{Subject: "12345"},
			upstream: "unconfigured",
			reason:   ReasonNoPolicy,
		},
		{
			name:     "identity with no subject denies",
			identity: Identity{},
			upstream: "github",
			reason:   ReasonNoIdentity,
		},
		{
			name:     "identity with no subject denies despite a listed email",
			identity: Identity{Email: "bvdrucker@gmail.com"},
			upstream: "github",
			reason:   ReasonNoIdentity,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := Decision{
				Identity: tc.identity,
				Upstream: tc.upstream,
				Allow:    tc.allow,
				Reason:   tc.reason,
				Rule:     tc.rule,
			}
			got := NewAuthorizer(testPolicy()).Authorize(tc.identity, tc.upstream)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("decision mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAuthorizeDeniesUnevaluableConditions(t *testing.T) {
	// config.Validate rejects these, but the authorizer fails closed on its own
	// so a policy that reached it another way cannot allow everyone.
	for _, tc := range []struct {
		name  string
		match config.Match
	}{
		{
			name:  "no conditions at all",
			match: config.Match{},
		},
		{
			name:  "claim with no name",
			match: config.Match{Claim: map[string]string{"": "svc@github"}},
		},
		{
			name:  "claim with no value",
			match: config.Match{Claim: map[string]string{"username": ""}},
		},
		{
			name:  "one evaluable condition alongside an empty one",
			match: config.Match{Subject: "12345", Claim: map[string]string{"username": ""}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := []config.Rule{{Upstream: "github", Allow: []config.Match{tc.match}}}
			identity := Identity{Subject: "12345", Email: "bvdrucker@gmail.com", Claims: map[string]any{"username": "svc@github"}}

			decision := NewAuthorizer(policy).Authorize(identity, "github")
			if decision.Allow {
				t.Fatalf("expected a denial, got %+v", decision)
			}
			if decision.Reason != ReasonNoMatch {
				t.Errorf("expected reason %q, got %q", ReasonNoMatch, decision.Reason)
			}
		})
	}
}

func TestAuthorizeWithoutAnAuthorizerDenies(t *testing.T) {
	var authorizer *Authorizer
	decision := authorizer.Authorize(Identity{Subject: "12345"}, "github")
	if decision.Allow {
		t.Fatalf("a nil authorizer must deny, got %+v", decision)
	}
	if decision.Reason != ReasonNoPolicy {
		t.Errorf("expected reason %q, got %q", ReasonNoPolicy, decision.Reason)
	}
}

func TestAuthorizeMatchesTheFirstRuleInOrder(t *testing.T) {
	policy := []config.Rule{
		{Upstream: "github", Allow: []config.Match{{Email: "bvdrucker@gmail.com"}}},
		{Upstream: "github", Allow: []config.Match{{Subject: "12345"}}},
	}
	identity := Identity{Subject: "12345", Email: "bvdrucker@gmail.com"}

	decision := NewAuthorizer(policy).Authorize(identity, "github")
	if !decision.Allow {
		t.Fatalf("expected an allow, got %+v", decision)
	}
	if want := "policy[0].allow[0]"; decision.Rule != want {
		t.Errorf("expected rule %q, got %q", want, decision.Rule)
	}
}
