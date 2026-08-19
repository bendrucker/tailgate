# Security Model

tailgate is an internet-facing authorization boundary. A validation gap in its request path is remote exposure of every MCP server behind it. [architecture.md](architecture.md) maps where these defenses live in the code.

## Trust Boundaries

- **The internet reaches tailgate through Funnel.** Tailscale terminates TLS at its edge, forwards plain HTTP, and strips tailnet identity, leaving the bearer token as the only identity signal tailgate has.
- **tsidp is the sole issuer.** Its access tokens are opaque, so validation is [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) introspection over the tailnet, where tsidp authenticates tailgate by its tailnet node identity and tailgate stores no secret. The introspection endpoint is accepted only on the configured issuer's origin, so a tampered discovery document cannot redirect live tokens elsewhere.
- **Upstreams are trusted with request bodies, never with credentials.** stdio upstreams are third-party code running as tailgate's user. Their children inherit tailgate's environment scrubbed of the tailnet auth key.
- **Authorization happens on the tailnet.** tsidp refuses `/authorize` over Funnel, and tailgate's own `/authorize` is only a redirect. The browser completing a grant must already be a tailnet device.

## Request-Path Defenses

### Fail Closed

Any verification, discovery, introspection, or authorization error denies the request. A verifier that cannot be built makes the upstream unavailable rather than unprotected, and an introspection transport failure is a `503`, never a `401` challenge and never an allow. A policy condition that cannot be evaluated, such as an email match against a token missing the claim, denies rather than being skipped. An upstream with no allow rules denies everyone, and a rule stating no conditions matches nobody. A panic anywhere in the request path returns `500` and never reaches an upstream.

### Credential Stripping

`httputil.ReverseProxy` forwards inbound headers by default, so `proxy.StripCredentials` runs twice: the router strips before dispatch and each transport strips again on the way out. It removes `Authorization`, `Proxy-Authorization`, `Forwarded`, and anything prefixed `X-Forwarded-` or `X-Tailgate-`, so nothing an upstream could mistake for tailgate's own assertion about the caller survives. The caller's identity travels in the request context, which no caller can write.

### Audience Binding

Every token carries an [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource audience, compared as an exact string against the requested upstream's canonical URI. Neither side normalizes, since tsidp matches its grant resources the same way and two spellings of one URI must never pass different checks. The audience, along with `exp`, `nbf`, and `sub`, is re-checked on every request including cache hits, so caching saves the introspection round trip and never a check.

### Exact-Segment Routing

The `/mcp/<name>` segment is matched by exact membership in the configured upstream set, with percent-encoded and non-clean paths rejected outright rather than normalized. `/mcp//x`, `/mcp/x/../y`, and `%2e%2e` never alias a real route, and the well-known metadata subtree routes to metadata rather than to an upstream.

### Origin Validation

A browser `Origin` that does not normalize to an origin tailgate is served from gets `403`, the DNS rebinding defense an internet-facing service needs. The opaque `null` origin is always refused. Requests without the header are non-browser clients and carry no ambient credentials to rebind.

### Session Binding

A session ID binds to the identity that minted it. Anyone else presenting the session gets the same `404` an unknown session gets, so a probe confirms nothing. The check keys off the presented header, never the declared protocol revision, so a caller cannot shed it by claiming the revision that dropped sessions. Only a session the server side actually minted can be claimed, and only a 2xx response records one.

### Auth Before Spawn

Token verification and the policy decision gate session creation, so a stdio child is never spawned for an unauthorized caller. The cap is per identity per upstream and counts live processes rather than registrations, so one caller can neither starve others nor hold children past the cap by churning sessions.

A stdio upstream takes `uid` and `gid`, applied before exec. A child left at tailgate's uid reads the node key out of `state_dir`, reads every other upstream's credentials out of the config file, and attaches to tailgate itself for a live bearer token, so withholding a variable from its environment buys nothing. Both are required together, and a tailgate that lacks the privilege to change a child's uid fails the spawn rather than starting it uncontained. The child drops tailgate's supplementary groups along with the uid, and it inherits tailgate's `HOME`, which it cannot write; name its own in `env`, whose entries are appended after tailgate's environment so the last value for a name wins.

This is a uid boundary, not a sandbox. The child still shares tailgate's network namespace, filesystem, and process table, so it reaches the tailnet, reads whatever is world-readable, and sees what else is running.

### Resource Limits

- `ReadHeaderTimeout` bounds the header phase against Slowloris.
- Bodies are buffered against a [size cap](deploying.md#limits) so overflow answers `413` cleanly.
- Introspection concurrency sheds load as `503` rather than queuing.
- Per-exchange timeouts bound every response except the streams that are contractually open-ended.

### Header and Body Agreement

Where the `2026-07-28` revision mirrors body fields into headers, tailgate refuses any request whose pair disagree, with the `400` and JSON-RPC code the spec assigns. Routing on a header while the upstream executes the body is how one request becomes two. The revision header must appear exactly once, and so must `Authorization` and the mirrored headers: a downstream reading a different copy than tailgate did is request smuggling.

### JSON-RPC Refusals

A `400` whose body is not a recognized JSON-RPC error tells a probing client the server predates the stateless revision, so every refusal tailgate originates at that status answers in the modern shape. Bare text talks callers into downgrading to revisions with weaker rules.

That error message names which validation the request failed. Each refusal at `400` describes a protocol mistake in the message the caller itself wrote, so naming it discloses nothing about the upstream, the identity, or tailgate's internals. The wording is written for the caller rather than taken from the internal error, whose own text is prefixed for the log. Every other status answers in status text alone, since those report a failure whose detail names the child command, the caller's cap, and other internals.

## Token and Log Handling

- Verification caches key on SHA-256 digests of the token, never the bearer itself.
- Negative verification results cache for thirty seconds against the five-minute positive ceiling, since negative entries are keyed by attacker-chosen strings.
- Every authorization decision is logged, denials at warn so a warn-filtered operator still sees every rejected caller. The raw introspection claims are never logged.
- `WWW-Authenticate` challenge values are sanitized to printable ASCII with quotes and backslashes escaped. A rejected request cannot smuggle header-splitting bytes into the response.
- The `/token` proxy forwards only `Authorization`, `Content-Type`, and `Accept`, caps bodies at 64 KiB in each direction, and logs only the response status.

## Known Limitations

- **Revocation lags by up to five minutes.** Introspection results cache until the token's `exp`, which tsidp caps at five minutes. Deleting a client revokes its tokens immediately at tsidp, but a cached allow can outlive that by the remaining lifetime.
- **A leaked tsidp client secret is introspection from anywhere.** tsidp accepts registered confidential-client credentials on `/introspect` from any source, including over Funnel, and introspection is not scoped to the caller's own tokens. This is tsidp behavior tailgate cannot change. tailgate itself avoids holding such a secret by introspecting over the tailnet.
- **Client secrets transit the token proxy.** `/token` is a reverse proxy. `client_secret_basic` and `client_secret_post` credentials transit tailgate in memory. They are never logged.
- **A tsidp restart invalidates every outstanding token.** Tokens live in tsidp's memory. This is an availability gap, and clients recover through their refresh flow.
- **Session bindings do not survive a restart.** The binding table is in memory. A restart forgets every session and answers `404`, the MCP signal to re-initialize. The failure is closed: a forgotten session can only be re-established by a caller whose token still verifies.
- **On-disk credentials rest on file permissions.** The node key and the TLS private key sit in `state_dir` and the upstream credentials in the config file, each protected by owner-only modes tailgate checks at startup. A process running as tailgate's own uid is inside that boundary, which is what per-upstream `uid` exists to keep stdio children out of. `tsnet` cannot report state encryption on darwin regardless of the store, so encryption at rest is unavailable there.
- **Process-group cleanup is Unix-only.** On other platforms, killing a stdio child does not reach grandchildren. A wrapper's real server can outlive its session. tailgate targets Unix deployments.
