//go:build unix

package config

import (
	"os"
	"testing"
)

// TestLoadRefusesConfigReadableBeyondItsOwner covers the mode boundary on the
// file holding every upstream's API keys. The documented location is a system
// path, and a file created there without thought is world-readable.
func TestLoadRefusesConfigReadableBeyondItsOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "owner read write", mode: 0o600},
		{name: "owner read only", mode: 0o400},
		{name: "owner all", mode: 0o700},
		{name: "group readable", mode: 0o640, wantErr: true},
		{name: "group writable", mode: 0o620, wantErr: true},
		{name: "other readable", mode: 0o604, wantErr: true},
		{name: "world readable", mode: 0o644, wantErr: true},
		{name: "world writable", mode: 0o666, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := ownerOnlyCopy(t, "testdata/tailgate.hujson")
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			_, err := Load(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
