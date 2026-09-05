package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// wantRootUsage is the published help text. It is spelled out here so that a
// change to the generated flag block shows up as a diff against what a user
// reads.
const wantRootUsage = `tailgate fronts MCP servers behind Tailscale Funnel. It joins the tailnet as
its own node, issues and verifies the OAuth tokens its clients present, and
proxies authorized requests to HTTP and stdio MCP upstreams at /mcp/<name>.

Usage:
  tailgate [flags]  serve the configured upstreams

Flags:
  -config string
    	path to the tailgate config file (default "tailgate.hujson")
  -open-login
    	open the interactive login URL in the default browser when the node has no auth key

Set TS_AUTHKEY to join the tailnet on the first start. The node key then
persists in node.state_dir, so later starts do not log in again.
`

// TestDispatch covers the argument handling that only main performs, including
// the exit codes, so it runs a real binary. A misspelled subcommand used to fall
// through to the serve path and start serving.
func TestDispatch(t *testing.T) {
	binary := buildTailgate(t)

	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{
			name:   "help prints usage to stdout",
			args:   []string{"help"},
			stdout: wantRootUsage,
		},
		{
			name:   "flag help prints usage",
			args:   []string{"-h"},
			stderr: wantRootUsage,
		},
		{
			name:   "unknown command is refused",
			args:   []string{"hlep", "-config", "x"},
			code:   2,
			stderr: "tailgate: unknown command \"hlep\"\nRun 'tailgate -h' for usage.\n",
		},
		{
			name:   "command after the flags is refused",
			args:   []string{"-config", "x", "help"},
			code:   2,
			stderr: "tailgate: unexpected argument \"help\"\nRun 'tailgate -h' for usage.\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, tc.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("run: %v", err)
				}
				code = exit.ExitCode()
			}
			if code != tc.code {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, tc.code, stderr.String())
			}
			if diff := cmp.Diff(tc.stdout, stdout.String()); diff != "" {
				t.Errorf("stdout differs:\n%s", diff)
			}
			if diff := cmp.Diff(tc.stderr, stderr.String()); diff != "" {
				t.Errorf("stderr differs:\n%s", diff)
			}
		})
	}
}

func buildTailgate(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "tailgate")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return binary
}
