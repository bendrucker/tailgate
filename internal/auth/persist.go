package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bendrucker/tailgate/internal/config"
)

// refreshFileVersion names the layout of the refresh file. A file of any other
// version is refused rather than guessed at, which costs its clients one
// consent.
const refreshFileVersion = 1

// refreshFile is the refresh table as it sits on disk. Only refresh tokens are
// written: an access token lives an hour, and a client whose access token a
// restart forgot redeems its refresh token on the 401.
type refreshFile struct {
	Version int             `json:"version"`
	Refresh []refreshRecord `json:"refresh"`
}

// refreshRecord is one refresh token's entry. Digest is the SHA-256 of the
// token, so nothing in the file can be presented as a bearer.
type refreshRecord struct {
	Digest   string         `json:"digest"`
	Subject  string         `json:"sub"`
	Email    string         `json:"email,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	ClientID string         `json:"client_id"`
	Resource string         `json:"resource"`
	Scopes   []string       `json:"scopes"`
	Family   string         `json:"family"`
	Issued   time.Time      `json:"issued"`
	Expires  time.Time      `json:"expires"`
}

// refreshStore writes the refresh table to a file after every change to it and
// reads it back at startup, so a restart keeps every client's grant. A failure
// either way is reported to onError and never stops tailgate: an unreadable
// file starts the table empty, which is the old in-memory behavior, and a
// failed write leaves the previous file in place.
type refreshStore struct {
	path    string
	onError func(error)
}

func (s *refreshStore) report(err error) {
	if s.onError != nil {
		s.onError(err)
	}
}

// load reads the records still live at now. A missing file is the first start
// and yields nothing. A file readable beyond its owner is refused unread, the
// same rule the state directory around it is held to.
func (s *refreshStore) load(now time.Time) ([]refreshRecord, error) {
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: stat refresh file: %w", err)
	}
	if err := config.OwnerOnly("refresh file "+s.path, info.Mode(), "every client's refresh grant"); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("auth: read refresh file: %w", err)
	}
	var file refreshFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("auth: parse refresh file %s: %w", s.path, err)
	}
	if file.Version != refreshFileVersion {
		return nil, fmt.Errorf("auth: refresh file %s is version %d, want %d", s.path, file.Version, refreshFileVersion)
	}
	live := file.Refresh[:0]
	for _, record := range file.Refresh {
		if now.Before(record.Expires) {
			live = append(live, record)
		}
	}
	return live, nil
}

// save replaces the file with records. The write goes to a temporary file in
// the same directory and is renamed over the old one, so a crash mid-write
// leaves the previous table rather than a truncated one. os.CreateTemp creates
// the file 0600.
func (s *refreshStore) save(records []refreshRecord) error {
	raw, err := json.Marshal(refreshFile{Version: refreshFileVersion, Refresh: records})
	if err != nil {
		return fmt.Errorf("auth: encode refresh file: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*")
	if err != nil {
		return fmt.Errorf("auth: write refresh file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("auth: write refresh file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("auth: write refresh file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("auth: write refresh file: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("auth: write refresh file: %w", err)
	}
	return nil
}

func recordOf(digest string, e grantEntry) refreshRecord {
	return refreshRecord{
		Digest:   base64.RawStdEncoding.EncodeToString([]byte(digest)),
		Subject:  e.grant.Identity.Subject,
		Email:    e.grant.Identity.Email,
		Claims:   e.grant.Identity.Claims,
		ClientID: e.grant.ClientID,
		Resource: e.grant.Resource,
		Scopes:   e.grant.Scopes,
		Family:   e.grant.family,
		Issued:   e.issued,
		Expires:  e.expires,
	}
}

func (r refreshRecord) entry() (string, grantEntry, error) {
	digest, err := base64.RawStdEncoding.DecodeString(r.Digest)
	if err != nil || len(digest) != 32 {
		return "", grantEntry{}, errors.New("auth: refresh file holds a malformed digest")
	}
	claims := r.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	return string(digest), grantEntry{
		grant: Grant{
			Identity: Identity{Subject: r.Subject, Email: r.Email, Claims: claims},
			ClientID: r.ClientID,
			Resource: r.Resource,
			Scopes:   r.Scopes,
			family:   r.Family,
		},
		issued:  r.Issued,
		expires: r.Expires,
	}, nil
}
