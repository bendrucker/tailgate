package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale/apitype"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/authserver"
	"github.com/bendrucker/tailgate/internal/cimd"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/resource"
)

type fakeServed struct {
	name  string
	steps *recorder
}

func (s *fakeServed) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Served-By", s.name)
	w.WriteHeader(http.StatusOK)
}

func (s *fakeServed) HasUpstream(name string) bool { return name == s.name }

func (s *fakeServed) Shutdown(context.Context) error {
	s.steps.record(s.name + " shutdown")
	return nil
}

func (s *fakeServed) Close() error {
	s.steps.record(s.name + " close")
	return nil
}

// writeConfig writes a loadable config naming one HTTP upstream and one
// allowed subject, with the owner-only mode Load insists on.
func writeConfig(t *testing.T, path, hostname, upstreamURL, subject string) {
	t.Helper()
	raw := fmt.Sprintf(`{
  "node": {"hostname": %q, "port": 443},
  "upstreams": [{"name": %q, "transport": "http", "url": %q}],
  "policy": [{"upstream": %q, "allow": [{"sub": %q}]}],
}`, hostname, testUpstream, upstreamURL, testUpstream, subject)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func servedBy(t *testing.T, routes *reloader) string {
	t.Helper()
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Header().Get("Served-By")
}

// fakeReloader builds a reloader over fake routers, each named for the order
// build produced it, and returns it with the teardown recorder.
func fakeReloader(t *testing.T, path string, buildErr func(n int) error) (*reloader, *recorder) {
	t.Helper()
	writeConfig(t, path, "tailgate", "http://127.0.0.1:9000/mcp", "1")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	steps := &recorder{}
	builds := 0
	routes, err := newReloader(path, cfg, func(*config.Config) (served, error) {
		builds++
		if err := buildErr(builds); err != nil {
			return nil, err
		}
		return &fakeServed{name: fmt.Sprintf("router-%d", builds), steps: steps}, nil
	}, discardLogger())
	if err != nil {
		t.Fatalf("newReloader: %v", err)
	}
	return routes, steps
}

func TestReloadSwapsAndRetires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	routes, steps := fakeReloader(t, path, func(int) error { return nil })

	if got := servedBy(t, routes); got != "router-1" {
		t.Fatalf("served by %q before any reload, want router-1", got)
	}
	if !routes.HasUpstream("router-1") || routes.HasUpstream("router-2") {
		t.Error("HasUpstream does not reflect the first router")
	}

	if err := routes.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := servedBy(t, routes); got != "router-2" {
		t.Errorf("served by %q after the reload, want router-2", got)
	}
	if routes.HasUpstream("router-1") || !routes.HasUpstream("router-2") {
		t.Error("HasUpstream does not reflect the reloaded router")
	}

	// The replaced router drains in the background alongside the current
	// one, and each is shut down before it is closed.
	if err := routes.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := routes.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recorded := steps.recorded()
	want := []string{"router-1 close", "router-1 shutdown", "router-2 close", "router-2 shutdown"}
	if diff := cmp.Diff(want, slices.Sorted(slices.Values(recorded))); diff != "" {
		t.Errorf("teardown steps differ:\n%s", diff)
	}
	for _, name := range []string{"router-1", "router-2"} {
		if slices.Index(recorded, name+" shutdown") > slices.Index(recorded, name+" close") {
			t.Errorf("%s was closed before it was shut down: %v", name, recorded)
		}
	}
}

// A SIGHUP that lands during shutdown must not build a router that nothing
// will drain, so a stopped reloader refuses and keeps serving the router it
// had.
func TestReloadRefusedAfterShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	routes, steps := fakeReloader(t, path, func(int) error { return nil })

	if err := routes.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := routes.Reload(); err == nil {
		t.Error("Reload after Shutdown succeeded")
	}
	if got := servedBy(t, routes); got != "router-1" {
		t.Errorf("served by %q after a refused reload, want router-1", got)
	}
	if err := routes.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if diff := cmp.Diff([]string{"router-1 shutdown", "router-1 close"}, steps.recorded()); diff != "" {
		t.Errorf("teardown steps differ:\n%s", diff)
	}
}

func TestReloadRefusals(t *testing.T) {
	buildErr := errors.New("favicon unreadable")
	for _, tc := range []struct {
		name string
		// edit changes the deployment between the first load and the reload.
		edit func(t *testing.T, path string)
		// buildErr is what the second build reports.
		buildErr error
		reason   string
	}{
		{
			name:   "file removed",
			edit:   func(t *testing.T, path string) { os.Remove(path) },
			reason: "no such file",
		},
		{
			name: "file does not parse",
			edit: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte(`{"node": `), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			reason: "parse",
		},
		{
			name: "file does not validate",
			edit: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte(`{"node": {"hostname": "tailgate", "port": 443}, "policy": [{"upstream": "ghost"}]}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			reason: "ghost",
		},
		{
			name: "node section changed",
			edit: func(t *testing.T, path string) {
				writeConfig(t, path, "gate", "http://127.0.0.1:9000/mcp", "1")
			},
			reason: "node.hostname changed",
		},
		{
			name:     "router does not build",
			edit:     func(*testing.T, string) {},
			buildErr: buildErr,
			reason:   buildErr.Error(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tailgate.hujson")
			routes, steps := fakeReloader(t, path, func(n int) error {
				if n > 1 {
					return tc.buildErr
				}
				return nil
			})
			tc.edit(t, path)

			err := routes.Reload()
			if err == nil {
				t.Fatal("Reload accepted the change")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error %q does not name %q", err, tc.reason)
			}
			if got := servedBy(t, routes); got != "router-1" {
				t.Errorf("served by %q after a refused reload, want router-1", got)
			}
			if steps := steps.recorded(); len(steps) != 0 {
				t.Errorf("a refused reload tore something down: %v", steps)
			}
		})
	}
}

func TestNodeChanges(t *testing.T) {
	running := config.Node{Hostname: "tailgate", StateDir: "/var/lib/tailgate", Port: 443, Tailnet: "example.ts.net", Tags: []string{"tag:tailgate"}}
	for _, tc := range []struct {
		name string
		edit func(n *config.Node)
		want []string
	}{
		{name: "unchanged", edit: func(*config.Node) {}},
		{name: "hostname", edit: func(n *config.Node) { n.Hostname = "gate" }, want: []string{"hostname"}},
		{name: "state dir", edit: func(n *config.Node) { n.StateDir = "/tmp/tailgate" }, want: []string{"state_dir"}},
		{name: "port", edit: func(n *config.Node) { n.Port = 8443 }, want: []string{"port"}},
		{name: "tailnet", edit: func(n *config.Node) { n.Tailnet = "" }, want: []string{"tailnet"}},
		{name: "tags", edit: func(n *config.Node) { n.Tags = nil }, want: []string{"tags"}},
		{name: "several", edit: func(n *config.Node) { n.Hostname, n.Port = "gate", 8443 }, want: []string{"hostname", "port"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded := running
			loaded.Tags = append([]string(nil), running.Tags...)
			tc.edit(&loaded)
			if diff := cmp.Diff(tc.want, nodeChanges(running, loaded)); diff != "" {
				t.Errorf("nodeChanges differs:\n%s", diff)
			}
		})
	}
}

// TestReloadKeepsTokens drives the real handler through a reload. A token
// issued before the reload must still verify afterward, and the policy that
// decides what it reaches must be the reloaded one.
func TestReloadKeepsTokens(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(respondJSON))
	t.Cleanup(upstream.Close)

	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	writeConfig(t, path, "tailgate", upstream.URL, "1")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	urls, err := resource.NewURLs(testFQDN, testPort)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}

	logger := discardLogger()
	tokens := auth.NewTokens()
	var routes *reloader
	authServer, err := authserver.New(authserver.Options{
		Resources:   urls,
		HasUpstream: func(name string) bool { return routes.HasUpstream(name) },
		Tokens:      tokens,
		Identify: func(context.Context, netip.AddrPort) (*apitype.WhoIsResponse, error) {
			return nil, errors.New("no tailnet in this test")
		},
		Clients: cimd.NewFetcher(http.DefaultClient),
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("authserver.New: %v", err)
	}
	routes, err = newReloader(path, cfg, func(cfg *config.Config) (served, error) {
		rt, err := handler(cfg, urls, tokens, authServer, logger, audit.New(logger))
		if err != nil {
			return nil, err
		}
		return rt, nil
	}, logger)
	if err != nil {
		t.Fatalf("newReloader: %v", err)
	}
	t.Cleanup(func() { routes.Close() })

	issued := tokens.Issue(auth.Grant{
		Identity: auth.Identity{Subject: "1", Email: "you@example.ts.net"},
		ClientID: "https://client.example.com/oauth/client",
		Resource: urls.ResourceURL(testUpstream),
		Scopes:   resource.SupportedScopes(),
	})
	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/mcp/"+testUpstream, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+issued.AccessToken)
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call(); got != http.StatusOK {
		t.Fatalf("before any reload: %d, want 200", got)
	}

	writeConfig(t, path, "tailgate", upstream.URL, "2")
	if err := routes.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := call(); got != http.StatusForbidden {
		t.Errorf("after the policy stopped allowing the subject: %d, want 403", got)
	}

	writeConfig(t, path, "tailgate", upstream.URL, "1")
	if err := routes.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := call(); got != http.StatusOK {
		t.Errorf("after the policy allowed the subject again: %d, want 200", got)
	}

	// The metadata for the upstream is served by whichever router is current,
	// and the authorization server's upstream check follows it.
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authserver.MetadataPath+"/mcp/"+testUpstream, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("authorization-server metadata under the upstream: %d, want 200", rec.Code)
	}
}
