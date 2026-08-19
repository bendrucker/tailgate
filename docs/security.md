# Security Model

tailgate is an internet-facing authorization boundary. A validation gap in its request path is remote exposure of every MCP server behind it. This document records what tailgate trusts, what it defends against, and what it knowingly does not solve. The same invariants appear in [CLAUDE.md](../CLAUDE.md) as the build contract held while changing the code, and [architecture.md](architecture.md) describes the machinery that enforces them.

## Trust Boundaries

- **The internet reaches tailgate through Funnel.** Tailscale terminates TLS at its edge and forwards plain HTTP. Funnel strips tailnet identity. That leaves the bearer token as the only identity signal tailgate has for any request.
- **tsidp is the sole issuer.** Its access tokens are opaque, so validation is [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) introspection over the tailnet, where tsidp authenticates tailgate by its tailnet node identity and tailgate stores no secret. Discovery is pinned to the configured issuer's origin. A tampered discovery document cannot redirect tokens elsewhere.
- **Upstreams are trusted with request bodies, never with credentials.** The client's token is stripped before forwarding, twice: once by the router and again by each transport. stdio upstreams are third-party code running as tailgate's user. Their children get an environment scrubbed of the tailnet auth key.
- **Authorization happens on the tailnet.** tsidp refuses `/authorize` over Funnel, and tailgate's own `/authorize` is only a redirect. The browser completing a grant must already be a tailnet device.

## Request-Path Defenses

### Fail Closed

Any verification, discovery, introspection, or authorization error denies the request. A verifier that cannot be built makes the upstream unavailable rather than unprotected, and an introspection transport failure is a `503`, never a `401` challenge and never an allow. A policy condition that cannot be evaluated, such as an email match against a token missing the claim, denies rather than being skipped, and an upstream with no policy rules denies everyone.

### Audience Binding

Every token carries an [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource audience, checked byte-for-byte against the requested upstream's canonical URI. A token minted for one upstream is useless against another. The audience, along with `exp`, `nbf`, and `sub`, is re-checked on every request, including cache hits, so caching only saves the introspection round trip and never a check.

### Exact-Segment Routing

The `/mcp/<name>` segment is matched by exact membership in the configured upstream set, with percent-encoded and non-clean paths rejected outright. `/mcp//x`, `/mcp/x/../y`, and `%2e%2e` never alias a real route, and the well-known metadata subtree routes to metadata rather than to an upstream.

### Origin Validation

A browser `Origin` that does not normalize to the canonical Funnel origin gets `403`, which is the defense against DNS rebinding for an internet-facing service. The opaque `null` origin is always refused. Requests without the header are non-browser clients and carry no ambient credentials to rebind.

### Session Binding

A session ID binds to the identity that minted it, whichever layer minted it: the router's table for HTTP upstreams, the transport itself for stdio children. Anyone else presenting the session gets the same `404` an unknown session gets. A probe confirms nothing. The check keys off the presented header, never the declared protocol revision. A caller cannot shed it by claiming the revision that dropped sessions. Only a session the server side actually minted can ever be claimed, and only a 2xx response records one.

### Auth Before Spawn

Token verification and the policy decision gate session creation. A stdio child is never spawned for an unauthorized caller. The child cap is per identity per upstream and counts live processes, so one caller can neither starve others nor hold processes past the cap by churning sessions.

### Resource Limits

- `ReadHeaderTimeout` bounds the header phase against Slowloris.
- Bodies are buffered against a size cap so overflow answers `413` cleanly.
- Introspection concurrency sheds load as `503` rather than queuing.
- Per-exchange timeouts bound every response except the streams that are contractually open-ended.

Timeout policy lives on the transport seam because a blanket server timeout cannot exempt one SSE response while bounding the next.

### Header and Body Agreement

Where the 2026-07-28 revision mirrors body fields into headers, tailgate refuses any request whose pair disagree, with the `400` and JSON-RPC code the spec assigns. Routing on a header while the upstream executes the body is how one request becomes two. The revision header itself must appear exactly once, and so must `Authorization` and the mirrored headers, since a downstream that reads a different copy than tailgate did is the same smuggling problem in miniature.

### JSON-RPC Refusals

A `400` whose body is not a recognized JSON-RPC error tells a probing client the server predates the stateless revision, so every refusal tailgate originates at that status answers in the modern shape. Bare text would talk callers into downgrading to revisions with weaker rules.

### Panic Recovery

A panic anywhere in the request path returns `500`. It never proceeds to an upstream.

## Token and Log Handling

- Verification caches key on SHA-256 digests of the token, never the bearer itself.
- Negative verification results cache for thirty seconds against the five-minute positive ceiling, since negative entries are keyed by attacker-chosen strings.
- Every authorization decision is logged, denials at warn so a warn-filtered operator still sees every rejected caller. The raw introspection claims are never logged.
- `WWW-Authenticate` challenge values are sanitized to printable ASCII with quotes escaped. A rejected request cannot smuggle header-splitting bytes into the response.
- The `/token` proxy forwards only `Authorization`, `Content-Type`, and `Accept`, caps bodies at 64 KiB in each direction, and logs only the response status.

## Known Limitations

- **Revocation lags by up to five minutes.** Introspection results cache until the token's `exp`, which tsidp caps at five minutes. Deleting a client revokes its tokens immediately at tsidp, but a cached allow can outlive that by the remaining lifetime.
- **A leaked tsidp client secret is introspection from anywhere.** tsidp accepts registered confidential-client credentials on `/introspect` from any source, including over Funnel, and introspection is not scoped to the caller's own tokens. This is tsidp behavior tailgate cannot change. tailgate itself avoids holding such a secret by introspecting over the tailnet.
- **Client secrets transit the token proxy.** `/token` is a reverse proxy. `client_secret_basic` and `client_secret_post` credentials transit tailgate in memory. They are never logged.
- **A tsidp restart invalidates every outstanding token.** Tokens live in tsidp's memory. This is an availability gap, and clients recover through their refresh flow.
- **Session bindings do not survive a restart.** The binding table is in memory. A restart forgets every session and answers `404`, the MCP signal to re-initialize. The failure is closed: a forgotten session can only be re-established by a caller whose token still verifies.
- **Process-group cleanup is Unix-only.** On other platforms, killing a stdio child does not reach grandchildren. A wrapper's real server can outlive its session. tailgate targets Unix deployments.
