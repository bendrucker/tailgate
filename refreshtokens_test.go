package main

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/keychain"
)

// fakeSecrets stands in for the keychain item. readErr, when set, is what
// every Read returns, the way a keychain that refuses an untrusted binary
// answers.
type fakeSecrets struct {
	secret  []byte
	readErr error
	adds    int
}

func (s *fakeSecrets) Read() ([]byte, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	if s.secret == nil {
		return nil, keychain.ErrNotFound
	}
	return s.secret, nil
}

func (s *fakeSecrets) Add(_ string, secret []byte) error {
	if s.secret != nil {
		return errors.New("duplicate item")
	}
	s.adds++
	s.secret = secret
	return nil
}

func (s *fakeSecrets) Delete() error {
	if s.readErr != nil {
		return s.readErr
	}
	if s.secret == nil {
		return keychain.ErrNotFound
	}
	s.secret = nil
	return nil
}

func testGrant() auth.Grant {
	return auth.Grant{
		Identity: auth.Identity{Subject: "12345", Email: "person@example.com"},
		ClientID: "https://client.example.com/oauth/client",
		Resource: "https://" + testFQDN + "/mcp/" + testUpstream,
		Scopes:   []string{"mcp"},
	}
}

func redeems(t *testing.T, tokens *auth.Tokens, refresh string) bool {
	t.Helper()
	_, err := tokens.Redeem(refresh, testGrant().ClientID, nil)
	return err == nil
}

func mustNewTokens(t *testing.T, logger *slog.Logger, node config.Node, secrets secretStore) *auth.Tokens {
	t.Helper()
	tokens, err := newTokens(logger, node, secrets)
	if err != nil {
		t.Fatalf("newTokens: %v", err)
	}
	return tokens
}

func TestNewTokensPersistsAcrossRestart(t *testing.T) {
	node := config.Node{StateDir: t.TempDir()}
	secrets := &fakeSecrets{}

	issued := mustNewTokens(t, discardLogger(), node, secrets).Issue(testGrant())
	if secrets.adds != 1 || len(secrets.secret) != auth.RefreshKeySize {
		t.Fatalf("first run stored %d keys of %d bytes, want one of %d", secrets.adds, len(secrets.secret), auth.RefreshKeySize)
	}
	if _, err := os.Stat(filepath.Join(node.StateDir, refreshTokenFile)); err != nil {
		t.Fatalf("no sealed file after an issue: %v", err)
	}

	restarted := mustNewTokens(t, discardLogger(), node, secrets)
	if secrets.adds != 1 {
		t.Errorf("a restart generated another key")
	}
	if !redeems(t, restarted, issued.RefreshToken) {
		t.Error("a refresh token did not redeem after a restart")
	}
}

func TestNewTokensMemoryOnly(t *testing.T) {
	node := config.Node{StateDir: t.TempDir(), TokenStore: config.TokenStoreMemory}
	secrets := &fakeSecrets{readErr: errors.New("the memory store must not touch the keychain")}

	issued := mustNewTokens(t, discardLogger(), node, secrets).Issue(testGrant())
	entries, err := os.ReadDir(node.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the memory store wrote %d files to state_dir", len(entries))
	}
	if redeems(t, mustNewTokens(t, discardLogger(), node, secrets), issued.RefreshToken) {
		t.Error("a refresh token from the memory store redeemed after a restart")
	}
}

func TestNewTokensKeychainRefusal(t *testing.T) {
	node := config.Node{StateDir: t.TempDir()}
	secrets := &fakeSecrets{}
	issued := mustNewTokens(t, discardLogger(), node, secrets).Issue(testGrant())
	path := filepath.Join(node.StateDir, refreshTokenFile)
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	key := secrets.secret
	secrets.readErr = errors.New("keychain: read: User interaction is not allowed. (OSStatus -25308)")
	var logs bytes.Buffer
	degraded := mustNewTokens(t, slog.New(slog.NewTextHandler(&logs, nil)), node, secrets)
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("serving from memory was not logged at error:\n%s", logs.String())
	}
	if redeems(t, degraded, issued.RefreshToken) {
		t.Error("a refresh token redeemed without the key")
	}
	degraded.Issue(testGrant())
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, sealed) {
		t.Errorf("serving from memory changed the sealed file: %v", err)
	}
	if !bytes.Equal(secrets.secret, key) {
		t.Error("a refused read replaced the key")
	}

	secrets.readErr = nil
	if !redeems(t, mustNewTokens(t, discardLogger(), node, secrets), issued.RefreshToken) {
		t.Error("the sealed file did not open once the keychain allowed the read")
	}
}

func TestNewTokensRefuses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		node    config.Node
		secrets *fakeSecrets
	}{
		{
			name:    "a build without keychain support",
			node:    config.Node{StateDir: "/var/lib/tailgate"},
			secrets: &fakeSecrets{readErr: keychain.ErrUnsupported},
		},
		{
			name:    "no state directory to keep the file in",
			node:    config.Node{},
			secrets: &fakeSecrets{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newTokens(discardLogger(), tc.node, tc.secrets); err == nil {
				t.Fatal("newTokens returned no error")
			} else if !strings.Contains(err.Error(), `"memory"`) {
				t.Errorf("error does not name the memory store as the remedy: %v", err)
			}
		})
	}
}

func TestForgetTokens(t *testing.T) {
	node := config.Node{StateDir: t.TempDir()}
	secrets := &fakeSecrets{}
	issued := mustNewTokens(t, discardLogger(), node, secrets).Issue(testGrant())

	if err := forgetTokens(node, secrets); err != nil {
		t.Fatalf("forgetTokens: %v", err)
	}
	if _, err := os.Stat(filepath.Join(node.StateDir, refreshTokenFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the sealed file is still in place: %v", err)
	}
	if secrets.secret != nil {
		t.Error("the key is still in the keychain")
	}
	if redeems(t, mustNewTokens(t, discardLogger(), node, secrets), issued.RefreshToken) {
		t.Error("a forgotten refresh token redeemed")
	}
	if secrets.adds != 2 {
		t.Errorf("the start after forgetting generated %d keys in total, want a fresh second one", secrets.adds)
	}
	if err := forgetTokens(node, &fakeSecrets{}); err != nil {
		t.Errorf("forgetting with nothing stored: %v", err)
	}
}
