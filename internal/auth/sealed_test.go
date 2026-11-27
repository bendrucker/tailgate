package auth

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, RefreshKeySize)
}

// restartable is a token store whose restart builds a fresh Tokens over the
// same file and clock, the way a new process would.
type restartable struct {
	t     *testing.T
	path  string
	key   []byte
	clock *testClock
	logs  *bytes.Buffer
	opts  []TokensOption
}

func newRestartable(t *testing.T, opts ...TokensOption) *restartable {
	return &restartable{
		t:     t,
		path:  filepath.Join(t.TempDir(), "refresh-tokens.sealed"),
		key:   testKey(7),
		clock: newTestClock(),
		logs:  &bytes.Buffer{},
		opts:  opts,
	}
}

func (r *restartable) start() *Tokens {
	r.t.Helper()
	f, err := NewSealedFile(r.path, r.key, slog.New(slog.NewTextHandler(r.logs, nil)))
	if err != nil {
		r.t.Fatalf("NewSealedFile: %v", err)
	}
	return NewTokens(append([]TokensOption{WithClock(r.clock.Now), WithSealedFile(f)}, r.opts...)...)
}

func redeems(tokens *Tokens, refresh string) bool {
	_, err := tokens.Redeem(refresh, testGrant().ClientID, nil)
	return err == nil
}

func TestSealedFileAcrossRestart(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())

	restarted := r.start()
	if _, err := restarted.Verify(t.Context(), issued.AccessToken, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify of an access token from before the restart = %v, want ErrInvalidToken", err)
	}
	grant, err := restarted.Redeem(issued.RefreshToken, testGrant().ClientID, nil)
	if err != nil {
		t.Fatalf("Redeem of a refresh token from before the restart: %v", err)
	}
	if grant.family != issued.family {
		t.Errorf("family = %q, want %q carried across the restart", grant.family, issued.family)
	}
	reissued := restarted.Issue(grant)
	id, err := restarted.Verify(t.Context(), reissued.AccessToken, testResource)
	if err != nil {
		t.Fatalf("Verify of the reissued access token: %v", err)
	}
	if id.Subject != "12345" || id.Email != "person@example.com" || id.Claims["name"] != "A Person" {
		t.Errorf("identity after restart = %+v", id)
	}
	if info, err := os.Stat(r.path); err != nil {
		t.Fatalf("stat: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %#o, want 0600", perm)
	}
}

func TestSealedFileStoresNoPresentableToken(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())
	sealed, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, token := range []string{issued.AccessToken, issued.RefreshToken} {
		if bytes.Contains(sealed, []byte(token)) {
			t.Error("the sealed file contains a minted token")
		}
	}
	if bytes.Contains(sealed, []byte("person@example.com")) {
		t.Error("the sealed file contains plaintext grant data")
	}
}

func TestSealedFileRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(r *restartable)
	}{
		{
			name: "a flipped ciphertext byte",
			damage: func(r *restartable) {
				sealed, err := os.ReadFile(r.path)
				if err != nil {
					r.t.Fatal(err)
				}
				sealed[len(sealed)-1] ^= 1
				if err := os.WriteFile(r.path, sealed, 0o600); err != nil {
					r.t.Fatal(err)
				}
			},
		},
		{
			name:   "a different key",
			damage: func(r *restartable) { r.key = testKey(8) },
		},
		{
			name: "a truncated file",
			damage: func(r *restartable) {
				if err := os.WriteFile(r.path, []byte("short"), 0o600); err != nil {
					r.t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRestartable(t)
			issued := r.start().Issue(testGrant())
			tc.damage(r)

			restarted := r.start()
			if restarted.refresh.len() != 0 {
				t.Errorf("loaded %d refresh tokens from a rejected file, want 0", restarted.refresh.len())
			}
			if redeems(restarted, issued.RefreshToken) {
				t.Error("a refresh token from a rejected file redeemed")
			}
			if _, err := os.Stat(r.path); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the rejected file is still in place: %v", err)
			}
			if !strings.Contains(r.logs.String(), "level=ERROR") {
				t.Errorf("rejection was not logged at error:\n%s", r.logs)
			}
		})
	}
}

func TestSealedFileDropsExpiredOnLoad(t *testing.T) {
	r := newRestartable(t)
	tokens := r.start()
	stale := tokens.Issue(testGrant())
	r.clock.Advance(DefaultRefreshTokenTTL - time.Hour)
	fresh := tokens.Issue(testGrant())
	r.clock.Advance(2 * time.Hour)

	restarted := r.start()
	if n := restarted.refresh.len(); n != 1 {
		t.Errorf("loaded %d refresh tokens, want only the unexpired one", n)
	}
	if redeems(restarted, stale.RefreshToken) {
		t.Error("an expired refresh token redeemed after a restart")
	}
	if !redeems(restarted, fresh.RefreshToken) {
		t.Error("an unexpired refresh token did not redeem after a restart")
	}
}

func TestSealedFilePersistsEveryRotation(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())

	var spent []string
	for range 3 {
		tokens := r.start()
		grant, err := tokens.Redeem(issued.RefreshToken, testGrant().ClientID, nil)
		if err != nil {
			t.Fatalf("Redeem: %v", err)
		}
		spent = append(spent, issued.RefreshToken)
		issued = tokens.Issue(grant)
	}

	restarted := r.start()
	for i, token := range spent {
		if redeems(restarted, token) {
			t.Errorf("refresh token %d redeemed again after a restart", i)
		}
	}
	if !redeems(restarted, issued.RefreshToken) {
		t.Error("the latest refresh token did not redeem after a restart")
	}
}

func TestSealedFilePersistsConsumptionWithoutReissue(t *testing.T) {
	r := newRestartable(t)
	issued := r.start().Issue(testGrant())
	if _, err := r.start().Redeem(issued.RefreshToken, "https://other.example.com/client", nil); err == nil {
		t.Fatal("another client's redemption succeeded")
	}
	if redeems(r.start(), issued.RefreshToken) {
		t.Error("a refresh token consumed by another client redeemed after a restart")
	}
}

func TestSealedFilePersistsRevocation(t *testing.T) {
	r := newRestartable(t)
	tokens := r.start()
	revoked := tokens.Issue(testGrant())
	kept := tokens.Issue(testGrant())
	tokens.Revoke(revoked)

	restarted := r.start()
	if redeems(restarted, revoked.RefreshToken) {
		t.Error("a revoked refresh token redeemed after a restart")
	}
	if !redeems(restarted, kept.RefreshToken) {
		t.Error("an unrelated refresh token did not redeem after a restart")
	}
}

func TestSealedFileKeepsTheCap(t *testing.T) {
	r := newRestartable(t, withTableSizes(4, 2))
	tokens := r.start()
	oldest := tokens.Issue(testGrant())
	middle := tokens.Issue(testGrant())
	newest := tokens.Issue(testGrant())

	restarted := r.start()
	if n := restarted.refresh.len(); n != 2 {
		t.Errorf("loaded %d refresh tokens, want the cap of 2", n)
	}
	if redeems(restarted, oldest.RefreshToken) {
		t.Error("the evicted refresh token redeemed after a restart")
	}
	for _, kept := range []Issued{middle, newest} {
		if !redeems(restarted, kept.RefreshToken) {
			t.Error("a refresh token within the cap did not redeem after a restart")
		}
	}
}

func TestSealedFileIgnoresUnknownRedemptions(t *testing.T) {
	r := newRestartable(t)
	r.start().Issue(testGrant())
	before, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	tokens := r.start()
	redeems(tokens, newToken())
	after, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("redeeming an unknown token rewrote the file")
	}
}

func TestNewSealedFileRefusesAShortKey(t *testing.T) {
	if _, err := NewSealedFile(filepath.Join(t.TempDir(), "f"), make([]byte, 16), nil); err == nil {
		t.Error("NewSealedFile accepted a 16-byte key")
	}
}
