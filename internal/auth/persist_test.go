package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// restartable builds a Tokens over one refresh file, so a test can stand up a
// second one over the same file the way a restarted process would.
type restartable struct {
	t      *testing.T
	clock  *testClock
	path   string
	errors []error
}

func newRestartable(t *testing.T) *restartable {
	return &restartable{t: t, clock: newTestClock(), path: filepath.Join(t.TempDir(), "refresh.json")}
}

func (r *restartable) start() *Tokens {
	return NewTokens(WithClock(r.clock.Now), WithRefreshFile(r.path, func(err error) {
		r.errors = append(r.errors, err)
	}))
}

func TestRefreshFileSurvivesRestart(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())

	restarted := r.start()
	if _, err := restarted.Verify(t.Context(), issued.AccessToken, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("access token after restart: err = %v, want ErrInvalidToken", err)
	}
	grant, err := restarted.Redeem(issued.RefreshToken, testGrant().ClientID, nil)
	if err != nil {
		t.Fatalf("Redeem after restart: %v", err)
	}
	if diff := cmp.Diff(testGrant(), grant, cmp.AllowUnexported(Grant{}), ignoreFamily); diff != "" {
		t.Errorf("grant after restart (-want +got):\n%s", diff)
	}
	if grant.family == "" {
		t.Error("grant after restart lost its family")
	}

	reissued := restarted.Issue(grant)
	if _, err := restarted.Verify(t.Context(), reissued.AccessToken, testResource); err != nil {
		t.Errorf("Verify the reissued access token: %v", err)
	}
	if len(r.errors) > 0 {
		t.Errorf("store errors: %v", r.errors)
	}
}

func TestRefreshFileKeepsRedemptionSingleUse(t *testing.T) {
	r := newRestartable(t)
	tokens := r.start()
	issued := tokens.Issue(testGrant())
	if _, err := tokens.Redeem(issued.RefreshToken, testGrant().ClientID, nil); err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	if _, err := r.start().Redeem(issued.RefreshToken, testGrant().ClientID, nil); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("redeemed token after restart: err = %v, want ErrInvalidToken", err)
	}
}

func TestRefreshFileKeepsRevocation(t *testing.T) {
	r := newRestartable(t)
	tokens := r.start()
	issued := tokens.Issue(testGrant())
	tokens.Revoke(issued)

	if _, err := r.start().Redeem(issued.RefreshToken, testGrant().ClientID, nil); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked token after restart: err = %v, want ErrInvalidToken", err)
	}
}

func TestRefreshFileDropsExpiredGrants(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())
	r.clock.Advance(DefaultRefreshTokenTTL)

	if _, err := r.start().Redeem(issued.RefreshToken, testGrant().ClientID, nil); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired token after restart: err = %v, want ErrInvalidToken", err)
	}
}

func TestRefreshFileHoldsDigestsOnly(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())

	raw, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), issued.RefreshToken) || strings.Contains(string(raw), issued.AccessToken) {
		t.Error("refresh file contains a bearer token")
	}
	info, err := os.Stat(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("refresh file mode = %#o, want 0600", perm)
	}
}

func TestRefreshFileUnreadableStartsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, path string)
	}{
		{
			name:  "not JSON",
			write: func(t *testing.T, path string) { writeFile(t, path, "{", 0o600) },
		},
		{
			name:  "another version",
			write: func(t *testing.T, path string) { writeFile(t, path, `{"version":2,"refresh":[]}`, 0o600) },
		},
		{
			name: "readable beyond its owner",
			write: func(t *testing.T, path string) {
				writeFile(t, path, `{"version":1,"refresh":[]}`, 0o644)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRestartable(t)
			tc.write(t, r.path)

			tokens := r.start()
			if len(r.errors) != 1 {
				t.Fatalf("store errors = %v, want one", r.errors)
			}
			if n := tokens.refresh.len(); n != 0 {
				t.Errorf("refresh table holds %d entries, want 0", n)
			}
			issued := tokens.Issue(testGrant())
			if _, err := r.start().Redeem(issued.RefreshToken, testGrant().ClientID, nil); err != nil {
				t.Errorf("a grant issued after the refusal does not survive a restart: %v", err)
			}
		})
	}
}

func TestRefreshFileMissingIsAFirstStart(t *testing.T) {
	r := newRestartable(t)
	r.start()
	if len(r.errors) > 0 {
		t.Errorf("store errors on a first start: %v", r.errors)
	}
}

var ignoreFamily = cmp.FilterPath(func(p cmp.Path) bool {
	return p.Last().String() == ".family"
}, cmp.Ignore())

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
