package router

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/resource"
)

var (
	errMissingToken           = errors.New("router: no bearer token")
	errMalformedAuthorization = errors.New("router: malformed Authorization header")
)

// authenticate proves the caller's identity for up, or writes the refusal and
// reports false. Every outcome is audited, including the ones that never reach
// policy, so the log shows why a caller was turned away before evaluation.
func (rt *Router) authenticate(rec *responseRecorder, r *http.Request, up *upstream) (auth.Identity, bool) {
	token, err := bearerToken(r.Header)
	if err != nil {
		reason, opts := ReasonNoToken, resource.ChallengeOptions{}
		if errors.Is(err, errMalformedAuthorization) {
			// RFC 6750 section 3.1: a credential was presented and could not be
			// parsed, which is a malformed request rather than a bad token.
			reason = ReasonMalformedAuthorization
			opts = resource.ChallengeOptions{Error: "invalid_request"}
		}
		rt.audit.Deny(r.Context(), auth.Identity{}, up.name, reason)
		rt.challenge(rec, up, opts)
		return auth.Identity{}, false
	}

	id, err := rt.verifier.Verify(r.Context(), token, up.resourceURL)
	switch {
	case err == nil:
		return id, true
	case errors.Is(err, auth.ErrInvalidToken):
		rt.audit.Deny(r.Context(), auth.Identity{}, up.name, ReasonInvalidToken)
		rt.challenge(rec, up, resource.ChallengeOptions{Error: "invalid_token"})
	default:
		// auth.ErrUnavailable and anything unclassified: tailgate cannot prove
		// the token either way, so it never challenges the client to
		// re-authenticate a credential that may be perfectly good.
		rt.logger.Error("token verification unavailable", "upstream", up.name, "err", err)
		rt.audit.Deny(r.Context(), auth.Identity{}, up.name, ReasonVerifierUnavailable)
		http.Error(rec, "verification unavailable", http.StatusServiceUnavailable)
	}
	return auth.Identity{}, false
}

// challenge answers 401 with the WWW-Authenticate value that points the client
// at the upstream's protected-resource metadata, which is how a client with no
// prior configuration discovers where to obtain a token.
func (rt *Router) challenge(rec *responseRecorder, up *upstream, opts resource.ChallengeOptions) {
	rec.Header().Set("WWW-Authenticate", rt.resources.Challenge(up.name, opts))
	http.Error(rec, "unauthorized", http.StatusUnauthorized)
}

// bearerToken extracts the RFC 6750 header credential. Repeated Authorization
// headers are malformed rather than resolved to the first: which one a proxy
// would forward is not decidable here.
func bearerToken(header http.Header) (string, error) {
	values := header.Values("Authorization")
	switch len(values) {
	case 0:
		return "", errMissingToken
	case 1:
	default:
		return "", errMalformedAuthorization
	}
	scheme, credential, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", errMalformedAuthorization
	}
	token := strings.TrimSpace(credential)
	if token == "" {
		return "", errMalformedAuthorization
	}
	return token, nil
}

// originAllowed validates the browser origin against DNS rebinding. A request
// with no Origin header is not from a browser and is allowed. A request that
// carries one must name an origin tailgate is served from.
func (rt *Router) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return rt.origins[normalizeOrigin(origin)]
}

// normalizeOrigin reduces an origin to scheme and authority with the scheme's
// default port removed, so one origin has one spelling on both sides of the
// comparison. It returns "" for anything that is not an absolute origin,
// including the opaque "null" origin, which then matches no allowlist entry.
func normalizeOrigin(origin string) string {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	scheme, host := strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Hostname())
	if host == "" {
		return ""
	}
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	switch scheme {
	case "http", "https":
	default:
		return ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

// limitBody caps the request body, answering 413 when the caller exceeds it.
// The body is read here rather than wrapped, because a limit discovered while
// the transport is already streaming to the upstream cannot be reported as a
// status: an MCP client request is one JSON-RPC message, so buffering it costs
// the cap at most.
func (rt *Router) limitBody(rec *responseRecorder, r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	if r.ContentLength > rt.maxBody {
		rt.tooLarge(rec, r)
		return false
	}

	body, err := io.ReadAll(http.MaxBytesReader(rec, r.Body, rt.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			rt.tooLarge(rec, r)
			return false
		}
		rt.logger.Debug("read request body", "err", err)
		http.Error(rec, "bad request", http.StatusBadRequest)
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return true
}

func (rt *Router) tooLarge(rec *responseRecorder, r *http.Request) {
	rt.logger.Warn("request body too large", "method", r.Method, "limit", rt.maxBody)
	http.Error(rec, "request body too large", http.StatusRequestEntityTooLarge)
}
