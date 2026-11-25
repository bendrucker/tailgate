package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// RefreshKeySize is the length of the AES-256-GCM key sealing the refresh
// token file.
const RefreshKeySize = 32

// sealedAAD binds the ciphertext to its purpose and format, so a file sealed
// under the same key for anything else fails to open here.
var sealedAAD = []byte("tailgate refresh tokens v1")

// SealedFile keeps the refresh-token table on disk under AES-256-GCM. The
// table keys on token digests. The plaintext contains nothing a caller could
// present as a token. Sealing is for integrity: anyone able to write the file
// could otherwise insert the digest of a token they know.
type SealedFile struct {
	path   string
	aead   cipher.AEAD
	logger *slog.Logger
}

// sealedRecord is one refresh-token entry as it is written to disk.
type sealedRecord struct {
	Digest   []byte         `json:"digest"`
	Subject  string         `json:"sub"`
	Email    string         `json:"email,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	ClientID string         `json:"client_id"`
	Resource string         `json:"resource"`
	Scopes   []string       `json:"scopes,omitempty"`
	Family   string         `json:"family"`
	Issued   time.Time      `json:"issued"`
	Expires  time.Time      `json:"expires"`
}

type sealedTable struct {
	Refresh []sealedRecord `json:"refresh"`
}

// NewSealedFile seals the refresh-token table at path under key, which must be
// RefreshKeySize bytes. logger receives load and save failures.
func NewSealedFile(path string, key []byte, logger *slog.Logger) (*SealedFile, error) {
	if len(key) != RefreshKeySize {
		return nil, fmt.Errorf("auth: refresh token key is %d bytes, want %d", len(key), RefreshKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &SealedFile{path: path, aead: aead, logger: logger}, nil
}

// load returns the stored entries, oldest first, and nothing when the file is
// missing. A damaged or forged file must never keep tailgate from starting.
// It is deleted and logged, which costs each client one login.
func (f *SealedFile) load() []cacheEntry[grantEntry] {
	sealed, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		f.logger.Error("refresh tokens unreadable, starting with none", "path", f.path, "err", err)
		return nil
	}
	entries, err := f.open(sealed)
	if err != nil {
		f.logger.Error("refresh token file rejected and deleted, starting with none: it was tampered with, damaged, or sealed under another key", "path", f.path, "err", err)
		if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			f.logger.Error("delete rejected refresh token file", "path", f.path, "err", err)
		}
		return nil
	}
	return entries
}

func (f *SealedFile) open(sealed []byte) ([]cacheEntry[grantEntry], error) {
	nonceSize := f.aead.NonceSize()
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("auth: refresh token file is %d bytes, shorter than its nonce", len(sealed))
	}
	plain, err := f.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], sealedAAD)
	if err != nil {
		return nil, fmt.Errorf("auth: refresh token file failed authentication: %w", err)
	}
	var table sealedTable
	if err := json.Unmarshal(plain, &table); err != nil {
		return nil, fmt.Errorf("auth: decode refresh token file: %w", err)
	}
	entries := make([]cacheEntry[grantEntry], 0, len(table.Refresh))
	for _, r := range table.Refresh {
		entries = append(entries, cacheEntry[grantEntry]{
			key: string(r.Digest),
			value: grantEntry{
				grant: Grant{
					Identity: Identity{Subject: r.Subject, Email: r.Email, Claims: r.Claims},
					ClientID: r.ClientID,
					Resource: r.Resource,
					Scopes:   r.Scopes,
					family:   r.Family,
				},
				issued:  r.Issued,
				expires: r.Expires,
			},
			expires: r.Expires,
		})
	}
	return entries, nil
}

// save replaces the file with entries, atomically: a crash leaves either the
// previous table or this one, never a torn write.
func (f *SealedFile) save(entries []cacheEntry[grantEntry]) error {
	table := sealedTable{Refresh: make([]sealedRecord, 0, len(entries))}
	for _, e := range entries {
		g := e.value.grant
		table.Refresh = append(table.Refresh, sealedRecord{
			Digest:   []byte(e.key),
			Subject:  g.Identity.Subject,
			Email:    g.Identity.Email,
			Claims:   g.Identity.Claims,
			ClientID: g.ClientID,
			Resource: g.Resource,
			Scopes:   g.Scopes,
			Family:   g.family,
			Issued:   e.value.issued,
			Expires:  e.expires,
		})
	}
	plain, err := json.Marshal(table)
	if err != nil {
		return err
	}
	nonce := make([]byte, f.aead.NonceSize())
	rand.Read(nonce)
	return writeAtomic(f.path, f.aead.Seal(nonce, nonce, plain, sealedAAD))
}

// writeAtomic writes data to a temporary file beside path, readable only by
// its owner, and renames it into place.
func writeAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
