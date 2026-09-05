# tailgate Build Guide

tailgate is a single Go binary that fronts MCP servers behind Tailscale Funnel, issues and verifies its own OAuth tokens, and proxies authorized requests to HTTP or stdio MCP upstreams. [`docs/architecture.md`](docs/architecture.md) maps the internals. Security invariants live in [security.md's Request-Path Defenses](docs/security.md#request-path-defenses).

## Locked Decisions

- **Tailscale.** Embedded via `tsnet`. tailgate joins the tailnet as its own node and serves Funnel itself, with no dependency on a host `tailscaled`. The deployment target is `launchd`.
- **Exposure.** Tailscale Funnel, whose supported ports constrain `node.port`. TLS terminates inside tailgate: `tsnet.ListenFunnel` returns a `tls.Listener` whose certificate `tsnet` obtains for the node, and the edge relays encrypted TCP. tailgate owns its own TLS configuration and private key.
- **Identity.** tailgate is the sole issuer. The person authorizing a client is identified by the tailnet connection their browser arrives on, resolved with `WhoIs`. Identity over Funnel is impossible rather than forbidden: a Funnel connection's own remote address is the Tailscale ingress relay, itself a tailnet peer, so the router never gives `/authorize` a peer address for one. On an MCP request the bearer token is the only identity signal, whichever way it arrived.
- **MCP auth.** tailgate is both the OAuth authorization server and the resource server: RFC 8414 metadata, RFC 9728 metadata, `401` with `WWW-Authenticate` naming the required scopes, and RFC 8707 audience validation. It never forwards a client's token to an upstream.
- **Clients.** Client ID Metadata Documents only. There is no client registry, no `/register`, and no secret anywhere in config or memory. A client is public, proves its request with S256 PKCE, and is bound to the redirect URIs its own origin publishes.
- **Tokens.** Opaque random strings looked up in memory, single-use refresh tokens rotated on redemption, every table capped. A restart forgets everything and clients recover through the ordinary `401`. Persistence was considered and rejected.
- **Consent.** The consent page is the only check at authorization. Any tailnet member can approve a client for themselves, and policy is what gates upstreams.
- **Protocol revisions.** tailgate speaks every revision from `2024-11-05` through `2026-07-28` and chooses per request. It fronts servers and serves clients it does not control, so it can never cut over to a single revision. Every revision difference lives in `internal/protocol`.
- **Routing.** Path prefix `/mcp/<name>`. Each upstream is a distinct protected resource whose audience is its canonical URI, and every resource string in the system comes from `resource.URLs`.
- **Authorization.** Claim-match policy, limited to the claims a token carries.
- **Config.** HuJSON. `SIGHUP` reloads it in place: upstreams, policy, and the favicon swap in behind a fresh router while the previous one drains, and the token store, authorization server, and CIMD cache stay put. The `node` section is fixed for the life of the process, since the tailnet node is joined once, and a reload that changes it is refused with the running configuration left serving.
- **stdio upstreams.** One child process per MCP session for a stateful caller, one per identity for a stateless one, with a concurrency cap and idle reaping either way.
- **Dependencies.** `go.mod` is the list and it stays short: adding one to an internet-facing binary needs a reason. Tokens are opaque lookups, so nothing is signed or parsed and no JOSE or JWT library belongs here.
- **Naming.** No numbered phases or steps in code or names, and no catch-all packages. Descriptive functions called in sequence instead.

## Settled Contracts

These come from research against pinned sources plus an end-to-end proxy test. Do not relitigate them.

### CIMD, `draft-ietf-oauth-client-id-metadata-document-00`

- **The `client_id` is an HTTPS URL with a non-empty path.** Refused: any scheme but `https`, an empty host, userinfo, a fragment, an empty or bare `/` path, and `.` or `..` path segments. A query string and a port are allowed.
- **The document is JSON.** `client_id` must equal the fetched URL by string comparison and `redirect_uris` must be non-empty. `client_name` is what the consent page shows, beside the `client_id` host. `client_uri` is optional and only linked.
- **No shared secret.** `token_endpoint_auth_method`, if present, must not name one, and `client_secret` or `client_secret_expires_at` in the document refuses it. A token request carrying `client_secret` gets `invalid_client`.
- **Metadata advertises `client_id_metadata_document_supported: true`.**
- **Fetching is an egress path.** Never a private, loopback, link-local, or tailnet target, checked after DNS resolution. No redirects. Bounded size, 16 KiB here. Cache within the document's `Cache-Control`, clamped to tailgate's own bounds, and never cache a failure.
- **`redirect_uri` matches exactly**, with the one exception RFC 8252 §7.3 requires: when both URIs are `http` on `127.0.0.1`, `[::1]`, or `localhost`, the port is ignored. The consent page shows the client host and the redirect host, because a hosted client naming a `localhost` redirect is the impersonation case the draft calls out.

### tsnet and Funnel, Pinned at `tailscale.com v1.102.2`

- **`ListenFunnel` without `tsnet.FunnelOnly()` serves tailnet peers and Funnel on one listener.** tailgate relies on this for the consent page.
- **A Funnel connection is an `*ipn.FunnelConn` under the `*tls.Conn`.** `Src` is the public client's address. The embedded conn's `RemoteAddr()` is the Tailscale ingress relay, a tailnet peer holding `PeerCapabilityIngress`. Calling `WhoIs` on it identifies the relay, never the person.
- **`WhoIs` resolves only single node addresses in the netmap**, never subnet routes or exit nodes. A public address fails the lookup.
- **`WhoIsResponse` carries `Node` and `UserProfile`.** `sub` is `UserProfile.ID` as a bare decimal, `email` is `LoginName`, `name` is `DisplayName`. A tagged node (`Node.IsTagged()`) has no person behind it and is refused.

### MCP, Verified Against the Published Specs

Two eras are live at once and tailgate serves both. Everything under "Both Eras" holds whatever revision a request declares.

#### Both Eras

- JSON-RPC batching stays removed. Each POST body is a single request, notification, or response.
- POSTed notifications get `202` with no body. POSTed requests get either one `application/json` object or a `text/event-stream`. What a POSTed response gets diverges by era.
- An invalid `Origin` gets `403`.
- `MCP-Protocol-Version` names the revision. An invalid value gets `400`. A missing header means assume `2025-03-26`, the last revision before the header existed.
- Client ID metadata documents (CIMD) are the preferred registration mechanism and DCR is deprecated as of `2026-07-28`, so serving CIMD clients and no `/register` is spec-compliant onboarding.
- MCP clients send the RFC 8707 `resource` on both the authorization and token requests. tailgate requires it on the authorization request and, when the token request repeats it, requires the two to agree.

#### 2024-11-05 Through 2025-11-25 (Stateful)

- A POSTed response gets `202` with no body, like a notification: these revisions let a server open a request of its own, so a client has something to answer.
- The server mints `Mcp-Session-Id` on the initialize response. Requests missing a required session header get `400`. An unknown or expired session gets `404`, which is what tells the client to re-initialize. `DELETE` terminates a session and may be refused with `405`.
- The standalone `GET` SSE stream may be refused with `405`. Resumption is always `GET` with `Last-Event-ID`, and replay is per stream, never across streams. Servers may close an SSE connection without terminating the stream, so a proxy must pass `id` and `retry` fields through unchanged and must not treat connection close as stream end.
- Session IDs must be cryptographically random visible ASCII, must never serve as authentication, and should be bound to the authenticated identity.

#### 2026-07-28 (Stateless)

- Protocol-level sessions and the `initialize` handshake are gone. Every request carries its own protocol version and client capabilities in `params._meta` under `io.modelcontextprotocol/*` keys. `Mcp-Session-Id` and `Last-Event-ID` are ignored, and `GET` and `DELETE` at the MCP endpoint get `405`. Cross-call state is a server-minted handle passed as an ordinary tool argument.
- Selected body fields are mirrored into HTTP headers so intermediaries can route without parsing bodies. `Mcp-Method` is required on every request, and `Mcp-Name` on `tools/call`, `prompts/get`, and `resources/read`. A value that cannot be plain ASCII is wrapped in the `=?base64?…?=` sentinel. Servers that read the body **MUST** reject a header that disagrees with it, with `400` and JSON-RPC code `-32020`.
- `Mcp-Param-{Name}` headers mirror tool arguments annotated with `x-mcp-header` in the tool's `inputSchema`. An intermediary that does not recognize one **MUST** forward it and otherwise ignore it. tailgate never sees an `inputSchema`, so every one of these is unrecognized to it.
- The standalone `GET` stream and `resources/subscribe` are replaced by `subscriptions/listen`, a POST whose response stream stays open. Anything that assumes a POST response completes promptly breaks on it. The server acknowledges with `notifications/subscriptions/acknowledged` as the first message on the stream, which is what opens the subscription. The JSON-RPC response to the listen request is what ends it, so a subscription that runs indefinitely never produces one. Servers should emit an SSE comment line as a keep-alive and set `X-Accel-Buffering: no`. There is no resumption, so a broken stream loses its request and the client reissues.
- `server/discover` is mandatory for servers, and the spec names it the backward-compatibility probe on stdio. The probe carries the caller's version and capabilities in `params._meta`, and a server that implements the method answers a probe without them as though the method itself were unknown. A child that answers it is of this era. The fallback **MUST NOT** be keyed to one error code: a legacy child has no notion of the method and refuses however its runtime does, and the SDKs disagree (`-32601` on TypeScript, `-32602` on Python, a code JSON-RPC does not define on Go). Only a code from the `-32020` to `-32099` range the spec reserves for itself identifies a child that implements the revision and still declined.
- Server-initiated JSON-RPC requests are gone. Sampling, elicitation, and roots arrive as an `InputRequiredResult`, and the client answers by retrying the original request with the input supplied. Every result carries a `resultType`. With no server-initiated request left to answer, a POSTed response is invalid input rather than a `202`.
- A `400` whose body is not a recognized JSON-RPC error tells a probing client the server is of the older era.
- Servers **SHOULD** put a `scope` parameter on the `WWW-Authenticate` challenge, and answer an insufficiently scoped token with `403` and `error="insufficient_scope"`.
- Roots, sampling, and logging are deprecated with a twelve-month window. `ping`, `logging/setLevel`, and `tasks/list` are removed. Tasks moved to an official extension.

## Curation

The settled contracts describe external systems, not this code, so nothing in the repository will contradict them once they go stale. Re-verify them against the source when the CIMD draft, the `tailscale.com` pin, or the MCP revision moves.
