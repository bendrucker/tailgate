//go:build unix

package stdiotransport

import (
	"math"
	"os/exec"
	"testing"
)

// TestRunAs covers the credential a contained child starts under. Zero is what
// the config spells "unset", so it can never reach a Credential: a child whose
// gid fell through to zero would run in the root group.
func TestRunAs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uid     int
		gid     int
		wantErr bool
	}{
		{name: "an ordinary uid and gid", uid: 501, gid: 20},
		{name: "root uid is refused", uid: 0, gid: 20, wantErr: true},
		{name: "root gid is refused", uid: 501, gid: 0, wantErr: true},
		{name: "negative uid is refused", uid: -1, gid: 20, wantErr: true},
		{name: "negative gid is refused", uid: 501, gid: -1, wantErr: true},
		{name: "uid past a uid_t is refused", uid: math.MaxUint32 + 1, gid: 20, wantErr: true},
		{name: "gid past a uid_t is refused", uid: 501, gid: math.MaxUint32 + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("true")
			isolateProcessGroup(cmd)

			err := runAs(cmd, tc.uid, tc.gid)
			if (err != nil) != tc.wantErr {
				t.Fatalf("runAs(%d, %d) = %v, wantErr %v", tc.uid, tc.gid, err, tc.wantErr)
			}
			if tc.wantErr {
				if cmd.SysProcAttr.Credential != nil {
					t.Errorf("a refused credential still reached the child")
				}
				return
			}
			credential := cmd.SysProcAttr.Credential
			if credential == nil {
				t.Fatal("runAs set no credential")
			}
			if credential.Uid != uint32(tc.uid) || credential.Gid != uint32(tc.gid) {
				t.Errorf("credential = uid %d gid %d, want uid %d gid %d", credential.Uid, credential.Gid, tc.uid, tc.gid)
			}
			// An empty Groups with NoSetGroups clear is what makes the child
			// call setgroups with an empty set, dropping tailgate's own.
			if len(credential.Groups) != 0 || credential.NoSetGroups {
				t.Errorf("child keeps supplementary groups: %+v", credential)
			}
			if !cmd.SysProcAttr.Setpgid {
				t.Errorf("the credential displaced the process group isolation")
			}
		})
	}
}
