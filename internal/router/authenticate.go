package router

import (
	"errors"
	"net/http"
	"strings"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/resource"
)

var (
	errMissingToken           = errors.New("router: no bearer token")
	errMalformedAuthorization = errors.New("router: malformed Authorization header")
)

// authenticateStep proves the caller's identity for the upstream. Every
// outcome is audited, including the ones that never reach policy, so the log
// shows why a caller was turned away before evaluation.
type authenticateStep struct{ rt *Router }

func (s authenticateStep) name() string { return "authenticate" }

func (s authenticateStep) check(ex *exchange) *refusal {
	token, err := bearerToken(ex.r.Header)
	if err != nil {
		reason, opts := ReasonNoToken, resource.ChallengeOptions{}
		if errors.Is(err, errMalformedAuthorization) {
			// RFC 6750 section 3.1: a credential was presented and could not be
			// parsed, which is a malformed request rather than a bad token.
			reason = ReasonMalformedAuthorization
			opts = resource.ChallengeOptions{Error: "invalid_request"}
		}
		return s.challenge(ex.up, http.StatusUnauthorized, opts, reason)
	}

	id, err := s.rt.verifier.Verify(ex.r.Context(), token, ex.up.resourceURL)
	switch {
	case err == nil:
		ex.identity = id
		return nil
	case errors.Is(err, auth.ErrInsufficientScope):
		// RFC 6750 section 3.1: the credential is good, so re-authenticating
		// under the same grant would produce the same token. The challenge still
		// rides along because a client reading only the status learns nothing
		// about which scope to ask for next time.
		return s.challenge(ex.up, http.StatusForbidden,
			resource.ChallengeOptions{Error: "insufficient_scope"}, ReasonInsufficientScope)
	case errors.Is(err, auth.ErrInvalidToken):
		return s.challenge(ex.up, http.StatusUnauthorized,
			resource.ChallengeOptions{Error: "invalid_token"}, ReasonInvalidToken)
	default:
		// auth.ErrUnavailable and anything unclassified: tailgate cannot prove
		// the token either way, so it never challenges the client to
		// re-authenticate a credential that may be perfectly good.
		s.rt.logger.Error("token verification unavailable", "upstream", ex.up.name, "err", err)
		return deny(http.StatusServiceUnavailable, "verification unavailable",
			denied(auth.Identity{}, ex.up.name, ReasonVerifierUnavailable))
	}
}

// challenge builds the refusal that points the client at the upstream's
// protected-resource metadata, which is how a client with no prior
// configuration discovers where to obtain a token. The status is a parameter
// because RFC 6750 answers a scope failure with 403 while every other refusal
// here is a 401.
func (s authenticateStep) challenge(up *upstream, status int, opts resource.ChallengeOptions, reason string) *refusal {
	return deny(status, strings.ToLower(http.StatusText(status)),
		denied(auth.Identity{}, up.name, reason)).
		withHeader("WWW-Authenticate", s.rt.resources.Challenge(up.name, opts))
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
