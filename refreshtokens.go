package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/keychain"
)

const (
	// keychainService is the service attribute of the keychain item holding
	// the refresh-token key. It matches the code signing identifier the
	// installed binary is signed with.
	keychainService = "dev.bendrucker.tailgate"
	keychainLabel   = "tailgate refresh token key"
	// refreshTokenFile is the sealed refresh-token table, inside state_dir.
	refreshTokenFile = "refresh-tokens.sealed"
)

// secretStore holds the key sealing the refresh-token file. keychain.Item
// implements it.
type secretStore interface {
	Read() ([]byte, error)
	Add(label string, secret []byte) error
	Delete() error
}

// keychainItem is the refresh-token key's item. The account is the absolute
// state_dir, so two deployments on one machine never share a key.
func keychainItem(node config.Node) (keychain.Item, error) {
	dir, err := filepath.Abs(node.StateDir)
	if err != nil {
		return keychain.Item{}, err
	}
	return keychain.Item{Service: keychainService, Account: dir}, nil
}

// newTokens builds the token store node.token_store asks for. secrets is nil
// outside tests, which selects the login keychain.
//
// A build without keychain support refuses to start. Memory-only is then
// always something the config states. When the keychain refuses the read, as
// it does for a binary its access list does not trust, tailgate serves from
// memory with the error logged and leaves the sealed file for a later start
// that can open it.
func newTokens(logger *slog.Logger, node config.Node, secrets secretStore) (*auth.Tokens, error) {
	if !node.PersistsTokens() {
		logger.Info("refresh tokens are kept in memory only, so a restart sends every client back through consent")
		return auth.NewTokens(), nil
	}
	if node.StateDir == "" {
		return nil, fmt.Errorf("node.token_store %q keeps refresh tokens in node.state_dir, which is not set. Set it, or set node.token_store to %q", config.TokenStoreKeychain, config.TokenStoreMemory)
	}
	if secrets == nil {
		item, err := keychainItem(node)
		if err != nil {
			return nil, err
		}
		secrets = item
	}

	key, err := refreshKey(secrets)
	switch {
	case errors.Is(err, keychain.ErrUnsupported):
		return nil, fmt.Errorf("node.token_store %q needs the macOS login keychain. Set node.token_store to %q to keep tokens in memory only: %w", config.TokenStoreKeychain, config.TokenStoreMemory, err)
	case err != nil:
		logger.Error("refresh token key unavailable, keeping tokens in memory only until a restart can read it", "err", err)
		return auth.NewTokens(), nil
	}

	path := filepath.Join(node.StateDir, refreshTokenFile)
	sealed, err := auth.NewSealedFile(path, key, logger)
	if err != nil {
		return nil, err
	}
	logger.Info("refresh tokens persist across restarts", "path", path)
	return auth.NewTokens(auth.WithSealedFile(sealed)), nil
}

// refreshKey reads the sealing key, generating and storing one on first run.
// Only a missing item is generated: any other failure leaves the item alone,
// since replacing a key the keychain merely refused to hand over would orphan
// the file it sealed.
func refreshKey(secrets secretStore) ([]byte, error) {
	key, err := secrets.Read()
	if err == nil {
		if len(key) != auth.RefreshKeySize {
			return nil, fmt.Errorf("the keychain item holds %d bytes, want %d", len(key), auth.RefreshKeySize)
		}
		return key, nil
	}
	if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}
	key = make([]byte, auth.RefreshKeySize)
	rand.Read(key)
	if err := secrets.Add(keychainLabel, key); err != nil {
		return nil, err
	}
	return key, nil
}

// forgetTokens revokes every refresh token: it deletes the sealed file and
// the key that sealed it. A tailgate still running keeps the tokens it has
// in memory, and anything it writes afterward is sealed under the deleted key,
// which the next start rejects.
func forgetTokens(node config.Node, secrets secretStore) error {
	var errs []error
	if node.StateDir != "" {
		err := os.Remove(filepath.Join(node.StateDir, refreshTokenFile))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if secrets == nil {
		item, err := keychainItem(node)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		secrets = item
	}
	err := secrets.Delete()
	if err != nil && !errors.Is(err, keychain.ErrNotFound) && !errors.Is(err, keychain.ErrUnsupported) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
