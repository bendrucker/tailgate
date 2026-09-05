# Security Model

tailgate is an internet-facing authorization boundary. A validation gap in its request path is remote exposure of every MCP server behind it. [architecture.md](architecture.md) maps where these defenses live in the code.

## Trust Boundaries

- **The internet reaches tailgate through Funnel.** The Funnel edge relays encrypted TCP and TLS terminates inside tailgate. A Funnel connection carries no tailnet identity, since its remote address is the Tailscale ingress relay, so the bearer token is the only identity signal an MCP request has.
- **tailgate is the sole issuer.** It mints opaque tokens into its own memory and verifies them by lookup, so nothing is signed, no key or secret is stored, and no dependency parses a credential. A client identifies itself with a [Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) at an HTTPS URL. The redirect URIs that document lists, together with PKCE, are what bind an authorization code to the client.
- **Upstreams are trusted with request bodies, never with credentials.** stdio upstreams are third-party code running as tailgate's user. Their children inherit tailgate's environment scrubbed of the tailnet auth key.
- **Authorization happens on the tailnet.** `/authorize` answers only a connection from a tailnet peer, whose address the node resolves to a user. A Funnel connection carries no peer address, because its remote address is the Tailscale ingress relay rather than the person, so a public browser is told to open the link from a tailnet device. The token endpoint and the metadata are public, since a client's backend has no tailnet identity.

## Request-Path Defenses

### Fail Closed

Any verification or authorization error denies the request. A policy condition that cannot be evaluated, such as an email match against a token missing the claim, denies rather than being skipped. An upstream with no allow rules denies everyone, and a rule stating no conditions matches nobody. A panic anywhere in the request path returns `500` and never reaches an upstream.

### Credential Stripping

`httputil.ReverseProxy` forwards inbound headers by default, so `proxy.StripCredentials` runs twice: the router strips before dispatch and each transport strips again on the way out. It removes `Authorization`, `Proxy-Authorization`, `Forwarded`, and anything prefixed `X-Forwarded-` or `X-Tailgate-`, so nothing an upstream could mistake for tailgate's own assertion about the caller survives. The caller's identity travels in the request context, which no caller can write.

### Audience Binding

Every token carries an [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource audience, compared as an exact string against the requested upstream's canonical URI. Neither side normalizes: the `resource` a client names must equal a configured upstream's canonical URI to the byte, and two spellings of one URI must never pass different checks. The audience, expiry, and subject are checked on every request.

### Client Identification

A `client_id` must be an HTTPS URL with a path, no userinfo, no fragment, and no dot segments, and the document fetched there must name exactly that URL. Fetching a URL a stranger chose is an egress path off an internet-facing process, so the fetch refuses every address that is not global unicast plus both tailnet ranges after DNS resolution, follows no redirects, caps the body at 16 KiB, and never caches a failure. A document that carries a secret or names a shared-secret authentication method is refused, and so is a token request carrying one.

The `redirect_uri` on an authorization request must exactly match an entry in the document, with the one exception [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252#section-7.3) requires for a loopback port. The consent page shows the host publishing the document and the host the code will be sent to, because a hosted client naming a `localhost` redirect is the impersonation the draft warns about.

### Consent

The person approving a client is whoever the tailnet says is behind the connection, and the pending authorization records their user ID at the moment the page renders. The decision must arrive from the same user over a tailnet connection within ten minutes, and each pending entry answers once. The router's `Origin` check covers the form against cross-site posts, and the pending handle is unguessable. A tagged node has no person behind it and is refused.

### Code and Token Handling

Every code is bound to the client, redirect URI, PKCE challenge, scopes, resource, and identity that produced it, and only S256 is accepted. A code is single-use, and a replay revokes the tokens it first issued, per [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2). A redemption refused for any reason consumes the code. Refresh tokens rotate on use, and one presented by a different client is consumed and refused rather than left for its owner.

### Exact-Segment Routing

The `/mcp/<name>` segment is matched by exact membership in the configured upstream set, with percent-encoded and non-clean paths rejected outright rather than normalized. `/mcp//x`, `/mcp/x/../y`, and `%2e%2e` never alias a real route, and the well-known metadata subtree routes to metadata rather than to an upstream.

### Origin Validation

A browser `Origin` that does not normalize to an origin tailgate is served from gets `403`, the DNS rebinding defense an internet-facing service needs. The opaque `null` origin is always refused. Requests without the header are non-browser clients and carry no ambient credentials to rebind.

### Session Binding

A session ID binds to the identity that minted it. Anyone else presenting the session gets the same `404` an unknown session gets, so a probe confirms nothing. The check keys off the presented header, never the declared protocol revision, so a caller cannot shed it by claiming the revision that dropped sessions. Only a session the server side actually minted can be claimed, and only a 2xx response records one.

### Auth Before Spawn

Token verification and the policy decision gate session creation, so a stdio child is never spawned for an unauthorized caller. The cap is per identity per upstream and counts live processes rather than registrations, so one caller can neither starve others nor hold children past the cap by churning sessions.

A stdio upstream takes `uid` and `gid`, applied before exec. A child left at tailgate's uid reads the node key out of `state_dir`, reads every other upstream's credentials out of the config file, and attaches to tailgate itself for a live bearer token, so withholding a variable from its environment buys nothing. Both are required together, and a tailgate that lacks the privilege to change a child's uid fails the spawn rather than starting it uncontained. The child drops tailgate's supplementary groups along with the uid, and it inherits tailgate's `HOME`, which it cannot write. Name its own in `env`, whose entries are appended after tailgate's environment so the last value for a name wins.

This is a uid boundary, not a sandbox. The child still shares tailgate's network namespace, filesystem, and process table, so it reaches the tailnet, reads whatever is world-readable, and sees what else is running.

### Resource Limits

- `ReadHeaderTimeout` bounds the header phase against Slowloris.
- Bodies are buffered against a [size cap](deploying.md#limits) so overflow answers `413` cleanly.
- Every in-memory table is capped. Token tables evict their oldest entry, and a full pending-authorization table refuses new consent pages rather than growing.
- Per-exchange timeouts bound every response except the streams that are contractually open-ended.

### Header and Body Agreement

Where the `2026-07-28` revision mirrors body fields into headers, tailgate refuses any request whose pair disagree, with the `400` and JSON-RPC code the spec assigns. Routing on a header while the upstream executes the body is how one request becomes two. The revision header must appear exactly once, and so must `Authorization` and the mirrored headers: a downstream reading a different copy than tailgate did is request smuggling.

### JSON-RPC Refusals

A `400` whose body is not a recognized JSON-RPC error tells a probing client the server predates the stateless revision, so every refusal tailgate originates at that status on an MCP path answers in the modern shape. Bare text talks callers into downgrading to revisions with weaker rules. The OAuth endpoints answer in their own grammar, since no client probes those for an MCP revision. In `internal/router` the rule is structural rather than a convention. A refusal's status selects its body format at the moment the refusal is written, so a `400` leaves in the JSON-RPC shape no matter which step built it.

That error message names which validation the request failed. Each refusal at `400` describes a protocol mistake in the request the caller itself wrote, so naming the mistake discloses nothing about the upstream, the identity, or tailgate's internals. The wording is the transport's own. The internal error carries a package prefix that belongs in the log and never on the wire. Every other status on that path answers in status text alone, since each reports a failure whose detail names the child command, the caller's cap, or other internals.

## Token and Log Handling

- Token, code, and pending-authorization tables key on SHA-256 digests of the value, never the value itself.
- Every authorization decision is logged, denials at warn so a warn-filtered operator still sees every rejected caller. Claims are never logged.
- `WWW-Authenticate` challenge values are sanitized to printable ASCII with quotes and backslashes escaped. A rejected request cannot smuggle header-splitting bytes into the response.
- `/authorize` and `/token` cap form bodies at 64 KiB and answer with `Cache-Control: no-store`. The log records the client, subject, and resource of each grant and never a code or token.

## Known Limitations

- **Revocation is a restart.** There is no revocation endpoint. An access token lives an hour and a refresh token thirty days, and the only way to end one early is to restart tailgate, which forgets every token.
- **A restart invalidates every outstanding token.** Tokens live in memory. This is an availability gap, and clients recover through the ordinary `401`, which sends the person back through consent.
- **Any tailnet member can authorize a client for themselves.** The consent page is the only check at authorization. Policy is what gates upstreams, so a token for a person no rule allows reaches nothing, and every attempt is audited.
- **A client is trusted at its own origin.** The document at the `client_id` URL is what binds a code to the client. Whoever controls that origin controls where the client's codes go, which is the draft's own trust model, and the consent page shows the person which host that is.
- **Session bindings do not survive a restart or a reload.** The binding table is in memory and belongs to the router a reload replaces. Either forgets every session and answers `404`, the MCP signal to re-initialize. The failure is closed: a forgotten session can only be re-established by a caller whose token still verifies.
- **On-disk credentials rest on file permissions.** The node key and the TLS private key sit in `state_dir` and the upstream credentials in the config file, each protected by owner-only modes tailgate checks at startup. A process running as tailgate's own uid is inside that boundary, which is what per-upstream `uid` exists to keep stdio children out of. `tsnet` cannot report state encryption on darwin regardless of the store, so encryption at rest is unavailable there.
- **Process-group cleanup is Unix-only.** On other platforms, killing a stdio child does not reach grandchildren. A wrapper's real server can outlive its session. tailgate targets Unix deployments.
