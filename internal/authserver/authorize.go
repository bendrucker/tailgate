package authserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"tailscale.com/client/tailscale/apitype"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/cimd"
	"github.com/bendrucker/tailgate/internal/resource"
)

// pendingAuthorization is a validated authorization request waiting on the
// person's decision. It is bound to the subject identified when the consent
// page was rendered, so the decision must come from the same person.
type pendingAuthorization struct {
	clientID    string
	redirectURI string
	state       string
	challenge   string
	scopes      []string
	upstream    string
	resource    string
	subject     string
}

// authorizationCode is an approved grant waiting to be redeemed.
type authorizationCode struct {
	grant       auth.Grant
	redirectURI string
	challenge   string
}

func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.serveConsent(w, r)
	case http.MethodPost:
		s.serveDecision(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveConsent validates an authorization request and renders the consent
// page. Failures before the redirect URI is validated are answered as pages,
// since there is nowhere trustworthy to send the browser. Failures after it
// go back to the client through the redirect URI, per RFC 6749 section
// 4.1.2.1.
func (s *Server) serveConsent(w http.ResponseWriter, r *http.Request) {
	peer := auth.PeerAddrFrom(r.Context())
	if !peer.IsValid() {
		s.renderNotOnTailnet(w)
		return
	}

	query := r.URL.Query()
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "scope", "resource"} {
		if len(query[key]) > 1 {
			s.renderError(w, http.StatusBadRequest, "Invalid authorization request", "The request repeats the "+key+" parameter.")
			return
		}
	}

	clientID := query.Get("client_id")
	clientURL, err := cimd.ParseClientID(clientID)
	if err != nil {
		s.logger.Warn("refusing authorization request", "client_id", clientID, "err", err)
		s.renderError(w, http.StatusBadRequest, "Unknown client", "The client_id is not a client metadata document URL, so tailgate cannot tell which application is asking.")
		return
	}
	client, err := s.clients.Fetch(r.Context(), clientID)
	if err != nil {
		s.logger.Warn("refusing authorization request", "client_id", clientID, "err", err)
		s.renderError(w, http.StatusBadRequest, "Unknown client", "tailgate could not load a valid client metadata document from the client_id URL, so it cannot tell which application is asking.")
		return
	}

	redirectURI, ok := resolveRedirectURI(query.Get("redirect_uri"), client.RedirectURIs)
	if !ok {
		s.logger.Warn("refusing authorization request", "client_id", clientID, "err", "redirect_uri is not registered in the client metadata document")
		s.renderError(w, http.StatusBadRequest, "Redirect not registered", "The redirect_uri is not one the client's metadata document registers, so tailgate will not send an authorization code there.")
		return
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "Redirect not registered", err.Error())
		return
	}

	state := query.Get("state")
	if query.Get("response_type") != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type", "only the code response type is supported")
		return
	}
	challenge := query.Get("code_challenge")
	if query.Get("code_challenge_method") != "S256" || !validCodeChallenge(challenge) {
		redirectError(w, r, redirectURI, state, "invalid_request", "PKCE with the S256 code_challenge_method is required")
		return
	}
	scopes, err := requestedScopes(query.Get("scope"))
	if err != nil {
		redirectError(w, r, redirectURI, state, "invalid_scope", err.Error())
		return
	}
	resourceURL := query.Get("resource")
	upstream, ok := s.upstreamFor(resourceURL)
	if !ok {
		redirectError(w, r, redirectURI, state, "invalid_target", "resource must be the canonical URL of a configured upstream")
		return
	}

	identity, err := s.identifyPeer(r, peer)
	if err != nil {
		redirectError(w, r, redirectURI, state, "access_denied", err.Error())
		return
	}

	handle, ok := s.pending.put(pendingAuthorization{
		clientID:    clientID,
		redirectURI: redirectURI,
		state:       state,
		challenge:   challenge,
		scopes:      scopes,
		upstream:    upstream,
		resource:    resourceURL,
		subject:     identity.Subject,
	})
	if !ok {
		redirectError(w, r, redirectURI, state, "temporarily_unavailable", "too many authorization requests are waiting on a decision")
		return
	}

	s.renderConsent(w, consentPage{
		Request:      handle,
		ClientName:   client.ClientName,
		ClientHost:   clientURL.Host,
		ClientURI:    client.ClientURI,
		RedirectHost: redirectURL.Host,
		Scopes:       scopes,
		Upstream:     upstream,
		Resource:     resourceURL,
		Person:       identity.Email,
		PersonName:   displayName(identity),
	})
}

// serveDecision consumes the pending request the consent form names and
// either mints a code or reports the refusal. The person is identified again,
// since the form arrived on a connection of its own.
func (s *Server) serveDecision(w http.ResponseWriter, r *http.Request) {
	peer := auth.PeerAddrFrom(r.Context())
	if !peer.IsValid() {
		s.renderNotOnTailnet(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "Invalid form", "tailgate could not read the consent form.")
		return
	}

	pending, ok := s.pending.take(r.PostForm.Get("request"))
	if !ok {
		s.renderError(w, http.StatusBadRequest, "Authorization request expired", "This consent page is no longer valid. Start the connection again from the client.")
		return
	}

	identity, err := s.identifyPeer(r, peer)
	if err != nil {
		redirectError(w, r, pending.redirectURI, pending.state, "access_denied", err.Error())
		return
	}
	if identity.Subject != pending.subject {
		s.logger.Warn("refusing consent from a different person", "client_id", pending.clientID, "sub", identity.Subject, "expected", pending.subject)
		redirectError(w, r, pending.redirectURI, pending.state, "access_denied", "the consent page was answered by a different person than it was shown to")
		return
	}
	if r.PostForm.Get("decision") != "approve" {
		s.logger.Info("authorization declined", "client_id", pending.clientID, "upstream", pending.upstream, "sub", identity.Subject)
		redirectError(w, r, pending.redirectURI, pending.state, "access_denied", "the person declined the request")
		return
	}

	code, ok := s.codes.put(authorizationCode{
		grant: auth.Grant{
			Identity: identity,
			ClientID: pending.clientID,
			Resource: pending.resource,
			Scopes:   pending.scopes,
		},
		redirectURI: pending.redirectURI,
		challenge:   pending.challenge,
	})
	if !ok {
		redirectError(w, r, pending.redirectURI, pending.state, "temporarily_unavailable", "too many authorization codes are waiting to be redeemed")
		return
	}

	s.logger.Info("authorization approved", "client_id", pending.clientID, "upstream", pending.upstream, "sub", identity.Subject)
	params := url.Values{"code": {code}}
	if pending.state != "" {
		params.Set("state", pending.state)
	}
	redirectWith(w, r, pending.redirectURI, params)
}

// identifyPeer resolves the connection's tailnet peer to a person. The error
// is safe to show the client: it names the category of refusal and nothing
// about the tailnet.
func (s *Server) identifyPeer(r *http.Request, peer netip.AddrPort) (auth.Identity, error) {
	who, err := s.identify(r.Context(), peer)
	if err != nil {
		s.logger.Warn("could not identify the authorizing person", "peer", peer, "err", err)
		return auth.Identity{}, errors.New("the person authorizing could not be identified on the tailnet")
	}
	identity, err := identityOf(who)
	if err != nil {
		s.logger.Warn("refusing the authorizing peer", "peer", peer, "err", err)
		return auth.Identity{}, err
	}
	return identity, nil
}

// The subject is the bare decimal tailnet user ID, so an allowlist written for
// it needs no prefix, and the email is the tailnet login name.
func identityOf(who *apitype.WhoIsResponse) (auth.Identity, error) {
	switch {
	case who == nil || who.Node == nil || who.UserProfile == nil:
		return auth.Identity{}, errors.New("the tailnet reported no person behind the connection")
	case who.Node.IsTagged():
		return auth.Identity{}, errors.New("a tagged node cannot authorize a client, since no person is behind it")
	case who.UserProfile.ID == 0 || who.UserProfile.LoginName == "":
		return auth.Identity{}, errors.New("the tailnet reported no user behind the connection")
	}
	return auth.Identity{
		Subject: strconv.FormatInt(int64(who.UserProfile.ID), 10),
		Email:   who.UserProfile.LoginName,
		Claims: map[string]any{
			"name": who.UserProfile.DisplayName,
			"node": who.Node.Name,
		},
	}, nil
}

func displayName(id auth.Identity) string {
	name, _ := id.Claims["name"].(string)
	return name
}

// requestedScopes parses a scope parameter against the supported set. A
// request naming no scope gets every supported one, which RFC 6749 section
// 3.3 allows as the server's default.
func requestedScopes(scope string) ([]string, error) {
	supported := resource.SupportedScopes()
	if scope == "" {
		return supported, nil
	}
	requested := strings.Fields(scope)
	for _, s := range requested {
		if !slices.Contains(supported, s) {
			return nil, fmt.Errorf("scope %q is not supported", s)
		}
	}
	return requested, nil
}
