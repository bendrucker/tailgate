package authserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/cimd"
)

// tokenResponse is the RFC 6749 section 5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// serveToken redeems an authorization code or a refresh token. Every client
// is public, so a request that offers client authentication is refused: a
// client that believes it has a secret with tailgate is misconfigured, and
// accepting the request would hide that.
func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "the request body is not a form")
		return
	}
	form := r.PostForm
	if _, _, ok := r.BasicAuth(); ok || form.Has("client_secret") {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client", "clients are public and no client authentication is accepted")
		return
	}
	clientID := form.Get("client_id")
	if _, err := cimd.ParseClientID(clientID); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client_id must be a client metadata document URL")
		return
	}

	switch form.Get("grant_type") {
	case "authorization_code":
		s.redeemCode(w, form, clientID)
	case "refresh_token":
		s.refresh(w, form, clientID)
	default:
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

// redeemCode exchanges a code for tokens. A code that was already redeemed
// revokes what its first redemption issued, per RFC 6749 section 4.1.2: a
// replay means the code leaked, and the tokens went to whoever redeemed it
// first.
func (s *Server) redeemCode(w http.ResponseWriter, form url.Values, clientID string) {
	code := form.Get("code")
	entry, ok := s.codes.take(code)
	if !ok {
		if issued, replayed := s.redeemed.take(code); replayed {
			s.tokens.Revoke(issued)
			s.logger.Warn("authorization code replayed, revoking the tokens it issued", "client_id", clientID)
		}
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is unknown, expired, or already redeemed")
		return
	}
	switch {
	case entry.grant.ClientID != clientID:
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code was issued to another client")
		return
	case form.Get("redirect_uri") != entry.redirectURI:
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	case !verifyPKCE(entry.challenge, form.Get("code_verifier")):
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
		return
	case form.Has("resource") && form.Get("resource") != entry.grant.Resource:
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the authorization request")
		return
	}

	issued := s.tokens.Issue(entry.grant)
	if !s.redeemed.set(code, issued) {
		s.logger.Warn("redeemed code table is full, so a replay of this code cannot revoke its tokens", "client_id", clientID)
	}
	s.logger.Info("issued tokens", "client_id", clientID, "sub", entry.grant.Identity.Subject, "resource", entry.grant.Resource)
	s.writeTokens(w, issued, entry.grant.Scopes)
}

// refusal is an OAuth error the token endpoint raises for a refresh request's
// own parameters, before the refresh token is consumed.
type refusal struct {
	code        string
	description string
}

func (r *refusal) Error() string { return r.code + ": " + r.description }

// refresh rotates a refresh token. The token is single use, and it is consumed
// only once the request's scope and resource are accepted, so a client that
// mistyped either keeps its token and can retry. A token another client
// presents is consumed as leaked.
func (s *Server) refresh(w http.ResponseWriter, form url.Values, clientID string) {
	requested := strings.Fields(form.Get("scope"))
	grant, err := s.tokens.Redeem(form.Get("refresh_token"), clientID, func(grant auth.Grant) error {
		for _, name := range requested {
			if !slices.Contains(grant.Scopes, name) {
				return &refusal{code: "invalid_scope", description: "scope " + strconv.Quote(name) + " was not granted"}
			}
		}
		if form.Has("resource") && form.Get("resource") != grant.Resource {
			return &refusal{code: "invalid_target", description: "resource does not match the grant"}
		}
		return nil
	})
	var refused *refusal
	switch {
	case errors.As(err, &refused):
		s.writeOAuthError(w, http.StatusBadRequest, refused.code, refused.description)
		return
	case err != nil:
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is unknown, expired, already used, or belongs to another client")
		return
	}
	if len(requested) > 0 {
		grant.Scopes = requested
	}

	issued := s.tokens.Issue(grant)
	s.logger.Info("refreshed tokens", "client_id", clientID, "sub", grant.Identity.Subject, "resource", grant.Resource)
	s.writeTokens(w, issued, grant.Scopes)
}

func (s *Server) writeTokens(w http.ResponseWriter, issued auth.Issued, scopes []string) {
	payload, err := json.Marshal(tokenResponse{
		AccessToken:  issued.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(issued.ExpiresIn.Seconds()),
		RefreshToken: issued.RefreshToken,
		Scope:        strings.Join(scopes, " "),
	})
	if err != nil {
		s.logger.Error("encoding token response", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	noStore(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.Write(payload)
}
