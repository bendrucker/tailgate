package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// wantRootUsage and wantGrantUsage are the published help text. They are spelled
// out here so that a change to the generated flag block shows up as a diff
// against what a user reads.
const wantRootUsage = `tailgate fronts MCP servers behind Tailscale Funnel. It joins the tailnet as
its own node, validates tsidp OIDC tokens, and proxies authorized requests to
HTTP and stdio MCP upstreams at /mcp/<name>.

Usage:
  tailgate [flags]        serve the configured upstreams
  tailgate grant [flags]  print the tsidp policy grant authorizing those upstreams

Flags:
  -config string
    	path to the tailgate config file (default "tailgate.hujson")
  -open-login
    	open the interactive login URL in the default browser when the node has no auth key

Set TS_AUTHKEY to join the tailnet on the first start. The node key then
persists in node.state_dir, so later starts do not log in again.

Run "tailgate grant -h" for its flags.
`

const wantGrantUsage = `Usage: tailgate grant [flags]

Print the tsidp application-capability grant authorizing the configured
upstreams, as one entry of the tailnet policy's "grants" array. Append it to
the policy that applies to your tailnet, and regenerate it when upstreams
change. Editing a resource string by hand denies every request with an
audience mismatch.

Generating never contacts the control server, so the grant can be reviewed and
applied before the node exists. That needs node.tailnet in the config, since
the resource URIs are built from the node's FQDN.

Flags:
  -allow-admin-ui
    	grant access to tsidp's admin UI
  -allow-dcr
    	grant dynamic client registration
  -config string
    	path to the tailgate config file (default "tailgate.hujson")
  -dst string
    	policy destination naming tsidp's node, comma separated (default "*")
  -src string
    	policy source, comma separated (default "autogroup:member")
  -users string
    	tsidp rule users, comma separated (default: the identities the config's policy allows)

A grant destination must be a tag, user, group, host alias, or address, so it
cannot be derived from the issuer URL. Narrow -dst when tsidp runs on a tagged
node.

Example:
  tailgate grant -config /etc/tailgate.hujson >> tailnet-policy/grants.hujson
`

func TestGrantCommandHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := grantCommand([]string{"-h"}, &out, &errOut); err != nil {
		t.Fatalf("grantCommand: %v", err)
	}
	if diff := cmp.Diff(wantGrantUsage, errOut.String()); diff != "" {
		t.Errorf("grant usage differs:\n%s", diff)
	}
	if out.String() != "" {
		t.Errorf("usage reached the grant stream:\n%s", out.String())
	}
}

func TestGrantCommandParseError(t *testing.T) {
	var out, errOut bytes.Buffer
	err := grantCommand([]string{"-nope"}, &out, &errOut)
	if !errors.Is(err, errReported) {
		t.Fatalf("grantCommand error = %v, want errReported", err)
	}
	if !strings.Contains(errOut.String(), "flag provided but not defined: -nope") {
		t.Errorf("expected the FlagSet to report the bad flag itself, got:\n%s", errOut.String())
	}
	if out.String() != "" {
		t.Errorf("a diagnostic reached the grant stream, which the usage tells operators to append to their policy:\n%s", out.String())
	}
}

// TestGrantCommandTrailingArgument covers a word that lost its leading dash. The
// flag it meant to set keeps its default, so a -users list meant to narrow the
// grant is silently dropped in favor of whatever the default resolves to.
func TestGrantCommandTrailingArgument(t *testing.T) {
	var out, errOut bytes.Buffer
	err := grantCommand([]string{"-config", "tailgate.hujson", "users", "alice"}, &out, &errOut)
	if !errors.Is(err, errReported) {
		t.Fatalf("grantCommand error = %v, want errReported", err)
	}
	if !strings.Contains(errOut.String(), `unexpected argument "users"`) {
		t.Errorf("expected the stray argument to be named, got:\n%s", errOut.String())
	}
	if out.String() != "" {
		t.Errorf("a grant was written despite the bad invocation:\n%s", out.String())
	}
}

// TestGrantCommandDefaults pins the flag defaults to grant.New's fallbacks. The
// flags carry the package constants, so a plain invocation and a programmatic
// caller that leaves Options empty must produce the same grant.
func TestGrantCommandDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	if err := os.WriteFile(path, []byte(`{
  "node": {"hostname": "tailgate", "tailnet": "example.ts.net", "port": 443},
  "oidc": {"issuer": "https://idp.example.ts.net"},
  "upstreams": [{"name": "docs", "transport": "http", "url": "http://127.0.0.1:9000/mcp"}],
  "policy": [{"upstream": "docs", "allow": [{"email": "ben@example.com"}]}],
}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out, errOut bytes.Buffer
	if err := grantCommand([]string{"-config", path}, &out, &errOut); err != nil {
		t.Fatalf("grantCommand: %v", err)
	}
	for _, want := range []string{`"autogroup:member"`, `"src"`, `"dst"`, `"users"`, `https://tailgate.example.ts.net/mcp/docs`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("grant output is missing %s:\n%s", want, out.String())
		}
	}
}

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
			name:   "grant help prints grant usage",
			args:   []string{"grant", "-h"},
			stderr: wantGrantUsage,
		},
		{
			name:   "unknown command is refused",
			args:   []string{"grnat", "-config", "x"},
			code:   2,
			stderr: "tailgate: unknown command \"grnat\"\nRun 'tailgate -h' for usage.\n",
		},
		{
			name:   "command after the flags is refused",
			args:   []string{"-config", "x", "grant"},
			code:   2,
			stderr: "tailgate: unexpected argument \"grant\"\nRun 'tailgate -h' for usage.\n",
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
