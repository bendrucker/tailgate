package site

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pngHeader is enough of a PNG for http.DetectContentType to name the type.
var pngHeader = []byte("\x89PNG\r\n\x1a\n")

func testSite(t *testing.T) *Site {
	t.Helper()
	path := filepath.Join(t.TempDir(), "favicon.ico")
	if err := os.WriteFile(path, pngHeader, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestNewRejectsMissingAndEmptyFiles(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "absent.ico")); err == nil {
		t.Error("New with a missing file succeeded; a broken deployment should fail at startup")
	}
	empty := filepath.Join(t.TempDir(), "empty.ico")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(empty); err == nil {
		t.Error("New with an empty file succeeded")
	}
}

func TestHandlesOnlyTheSitePaths(t *testing.T) {
	s := testSite(t)
	for path, want := range map[string]bool{
		RootPath:       true,
		FaviconPath:    true,
		"/mcp/things":  false,
		"/favicon.png": false,
	} {
		if got := s.Handles(path); got != want {
			t.Errorf("Handles(%q) = %v, want %v", path, got, want)
		}
	}
}

// The favicon and the root page's icon link are the two places an icon
// crawler looks, so the icon must come back typed by its content and the page
// must point at it.
func TestServesFaviconAndLinkingRootPage(t *testing.T) {
	s := testSite(t)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, FaviconPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("favicon status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("favicon Content-Type = %q, want image/png", got)
	}
	if rec.Body.String() != string(pngHeader) {
		t.Error("favicon body is not the configured file")
	}

	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, RootPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("root status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<link rel="icon" href="/favicon.ico">`) {
		t.Error("root page does not link the favicon")
	}
}

func TestRefusesMethodsBesidesGetAndHead(t *testing.T) {
	rec := httptest.NewRecorder()
	testSite(t).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, RootPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

func TestHeadOmitsTheBody(t *testing.T) {
	rec := httptest.NewRecorder()
	testSite(t).ServeHTTP(rec, httptest.NewRequest(http.MethodHead, FaviconPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD body = %d bytes, want none", rec.Body.Len())
	}
}

// TestNewRejectsFilesThatAreNotImages defends the one origin tailgate is
// trusted on. The type is sniffed, so a favicon path pointed at markup would
// be served as HTML and run its script there.
func TestNewRejectsFilesThatAreNotImages(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "png", content: "\x89PNG\r\n\x1a\n"},
		{name: "icon", content: "\x00\x00\x01\x00"},
		{name: "html doctype", content: "<!doctype html><script>alert(1)</script>", wantErr: true},
		{name: "html element", content: "<html><script>alert(1)</script></html>", wantErr: true},
		{name: "xml declared svg", content: `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`, wantErr: true},
		{name: "bare svg", content: `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "favicon.ico")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := New(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestResponsesRefuseSniffing(t *testing.T) {
	s := testSite(t)
	for _, path := range []string{RootPath, FaviconPath} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s X-Content-Type-Options = %q, want nosniff", path, got)
		}
	}
}
