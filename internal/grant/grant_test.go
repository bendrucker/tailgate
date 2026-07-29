package grant

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bendrucker/tailgate/internal/resource"
	"github.com/google/go-cmp/cmp"
)

func urls(t *testing.T) *resource.URLs {
	t.Helper()
	u, err := resource.NewURLs("tailgate.example-name.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	return u
}

func TestNew(t *testing.T) {
	for _, tc := range []struct {
		name          string
		names         []string
		opts          Options
		wantSrc       []string
		wantDst       []string
		wantUsers     []string
		wantResources []string
		wantErr       string
	}{
		{
			name:      "defaults are wildcards the policy accepts",
			names:     []string{"github", "files"},
			wantSrc:   []string{"autogroup:member"},
			wantDst:   []string{"*"},
			wantUsers: []string{"*"},
			wantResources: []string{
				"https://tailgate.example-name.ts.net/mcp/github",
				"https://tailgate.example-name.ts.net/mcp/files",
			},
		},
		{
			name:  "explicit envelope overrides every default",
			names: []string{"github"},
			opts: Options{
				Src:   []string{"group:eng"},
				Dst:   []string{"tag:tsidp"},
				Users: []string{"ben@example.com"},
			},
			wantSrc:       []string{"group:eng"},
			wantDst:       []string{"tag:tsidp"},
			wantUsers:     []string{"ben@example.com"},
			wantResources: []string{"https://tailgate.example-name.ts.net/mcp/github"},
		},
		{
			name:    "no upstreams is an error",
			names:   nil,
			wantErr: "no upstreams",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := New(urls(t), tc.names, tc.opts)

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			if diff := cmp.Diff(tc.wantSrc, g.Src); diff != "" {
				t.Errorf("src differs:\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantDst, g.Dst); diff != "" {
				t.Errorf("dst differs:\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantResources, g.Resources()); diff != "" {
				t.Errorf("resources differ:\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantUsers, g.App[Capability][0].Users); diff != "" {
				t.Errorf("users differ:\n%s", diff)
			}
		})
	}
}

// The whole point of generating the grant is that tsidp compares the strings
// byte-for-byte, so a resource in the grant must equal ResourceURL exactly.
func TestResourcesMatchResourceURL(t *testing.T) {
	u := urls(t)
	names := []string{"github", "files"}

	g, err := New(u, names, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i, name := range names {
		if expected := u.ResourceURL(name); g.Resources()[i] != expected {
			t.Errorf("resource %q is %q, want %q", name, g.Resources()[i], expected)
		}
	}
}

func TestHuJSONParsesAsAGrantEntry(t *testing.T) {
	g, err := New(urls(t), []string{"github"}, Options{AllowDCR: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rendered, err := g.HuJSON()
	if err != nil {
		t.Fatalf("HuJSON: %v", err)
	}

	// The rendered form is an entry of a grants array, so it parses only once
	// wrapped in one, with the comments and trailing comma HuJSON permits.
	policy := "{\"grants\": [\n" + strings.TrimSuffix(strings.SplitN(string(rendered), "\n", 3)[2], ",\n") + "\n]}"

	var parsed struct {
		Grants []Grant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(policy), &parsed); err != nil {
		t.Fatalf("rendered grant does not parse inside a grants array: %v\n%s", err, policy)
	}
	if len(parsed.Grants) != 1 {
		t.Fatalf("expected one grant, got %d", len(parsed.Grants))
	}
	if diff := cmp.Diff(g.Resources(), parsed.Grants[0].Resources()); diff != "" {
		t.Errorf("round-tripped resources differ:\n%s", diff)
	}
	if !parsed.Grants[0].App[Capability][0].AllowDCR {
		t.Error("expected allow_dcr to survive rendering")
	}
}
