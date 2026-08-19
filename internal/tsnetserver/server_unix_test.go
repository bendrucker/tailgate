//go:build unix

package tsnetserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewRefusesStateDirReadableBeyondItsOwner covers the mode boundary on the
// directory holding the node key. tsnet creates it 0700, but MkdirAll leaves an
// existing directory at whatever mode it already had, so a pre-created path is
// never narrowed.
func TestNewRefusesStateDirReadableBeyondItsOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "owner all", mode: 0o700},
		{name: "owner read execute", mode: 0o500},
		{name: "group readable", mode: 0o750, wantErr: true},
		{name: "group writable", mode: 0o730, wantErr: true},
		{name: "other readable", mode: 0o705, wantErr: true},
		{name: "world readable", mode: 0o755, wantErr: true},
		{name: "world writable", mode: 0o777, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			t.Cleanup(func() { os.Chmod(dir, 0o700) })

			srv, err := New(Config{Hostname: "tailgate", StateDir: dir, Port: 443})
			if (err != nil) != tc.wantErr {
				t.Fatalf("New error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}
			if srv != nil {
				t.Errorf("New returned a server alongside an error")
			}
			if !strings.Contains(err.Error(), dir) {
				t.Errorf("error = %q, want it to name the state dir", err)
			}
			if !strings.Contains(err.Error(), "node key") {
				t.Errorf("error = %q, want it to name what the directory holds", err)
			}
		})
	}
}

func TestNewStateDirPaths(t *testing.T) {
	existing := t.TempDir()
	file := filepath.Join(existing, "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, tc := range []struct {
		name    string
		dir     string
		wantErr string
	}{
		{name: "unset is tsnet's to choose"},
		{name: "an absent dir is left to tsnet to create", dir: filepath.Join(existing, "missing")},
		{name: "a file is not a state dir", dir: file, wantErr: "is not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{Hostname: "tailgate", StateDir: tc.dir, Port: 443})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
