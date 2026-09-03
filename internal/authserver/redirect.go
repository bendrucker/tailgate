package authserver

import (
	"net/http"
	"net/url"

	"github.com/bendrucker/tailgate/internal/cimd"
)

// resolveRedirectURI picks the redirect URI an authorization request will
// return to. A requested URI must match one the client's document registers
// exactly, per RFC 9700 section 4.1.3, with the RFC 8252 section 7.3 exception
// that a loopback URI may vary its port. A request that names none is served
// only when the document registers exactly one, per RFC 6749 section 3.1.2.3.
func resolveRedirectURI(requested string, registered []string) (string, bool) {
	if requested == "" {
		if len(registered) == 1 {
			return registered[0], true
		}
		return "", false
	}
	for _, candidate := range registered {
		if candidate == requested || loopbackMatch(candidate, requested) {
			return requested, true
		}
	}
	return "", false
}

// loopbackMatch reports whether two http loopback URIs differ only by port.
func loopbackMatch(registered, requested string) bool {
	a, err := url.Parse(registered)
	if err != nil {
		return false
	}
	b, err := url.Parse(requested)
	if err != nil {
		return false
	}
	if a.Scheme != "http" || b.Scheme != "http" || !cimd.IsLoopbackHost(a.Hostname()) || a.Hostname() != b.Hostname() {
		return false
	}
	return a.Path == b.Path && a.RawQuery == b.RawQuery && a.Fragment == "" && b.Fragment == ""
}

// redirectWith sends the browser back to redirectURI with params added to its
// query, keeping any query the client registered. GET answers 302 and a form
// POST answers 303, so the browser makes a GET either way.
func redirectWith(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	query := target.Query()
	for key, values := range params {
		for _, value := range values {
			query.Set(key, value)
		}
	}
	target.RawQuery = query.Encode()

	noStore(w.Header())
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, target.String(), status)
}

// redirectError reports an authorization failure to the client through its
// redirect URI, as RFC 6749 section 4.1.2.1 has it once the redirect URI is
// validated.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	params := url.Values{"error": {code}}
	if description != "" {
		params.Set("error_description", description)
	}
	if state != "" {
		params.Set("state", state)
	}
	redirectWith(w, r, redirectURI, params)
}
