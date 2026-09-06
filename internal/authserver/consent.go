package authserver

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strconv"
)

//go:embed consent.html
var pagesHTML string

// pages holds the consent page and the error page. Both are rendered with
// html/template, so every value the request supplied is escaped.
var pages = template.Must(template.New("pages").Parse(pagesHTML))

// consentPage is what the person sees before deciding. The client is shown by
// the name its document claims and by the host that published the document,
// since the name is the client's own assertion and the host is what the
// draft has the server display.
type consentPage struct {
	Request      string
	ClientName   string
	ClientHost   string
	ClientURI    string
	RedirectHost string
	Scopes       []string
	Upstream     string
	Resource     string
	Person       string
	PersonName   string
}

type errorPage struct {
	Title  string
	Detail string
}

func (s *Server) renderConsent(w http.ResponseWriter, page consentPage) {
	s.renderPage(w, http.StatusOK, "consent", page)
}

func (s *Server) renderError(w http.ResponseWriter, status int, title, detail string) {
	s.renderPage(w, status, "error", errorPage{Title: title, Detail: detail})
}

// renderNotOnTailnet answers a browser that reached /authorize over
// Funnel. The connection carries no tailnet identity to resolve, so
// identification is impossible there.
func (s *Server) renderNotOnTailnet(w http.ResponseWriter) {
	s.renderError(w, http.StatusForbidden, "Open this page from your tailnet", "Authorizing a client requires knowing who you are, and only a connection from a device on the tailnet carries that. Open the same URL from a device signed in to the tailnet.")
}

func (s *Server) renderPage(w http.ResponseWriter, status int, name string, data any) {
	var body bytes.Buffer
	if err := pages.ExecuteTemplate(&body, name, data); err != nil {
		s.logger.Error("rendering page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	noStore(h)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(body.Len()))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	// same-origin rather than no-referrer, which this page cannot use. Under
	// no-referrer a browser serializes the Origin of a non-GET navigation as
	// the opaque "null" rather than omitting it, so the consent form's own
	// POST back to /authorize arrives at an origin check that refuses null and
	// no one can ever approve a client. same-origin leaves the real Origin on
	// that POST and still sends no referrer to the client's redirect_uri,
	// which is what keeps the authorization request's parameters off the wire.
	h.Set("Referrer-Policy", "same-origin")
	w.WriteHeader(status)
	w.Write(body.Bytes())
}
