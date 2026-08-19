# tailgate Build Guide

tailgate is a single Go binary that fronts MCP servers behind Tailscale Funnel, validates tsidp OIDC tokens, and proxies authorized requests to HTTP or stdio MCP upstreams. [`docs/architecture.md`](docs/architecture.md) maps the internals. Security invariants live in [security.md's Request-Path Defenses](docs/security.md#request-path-defenses).

## Locked Decisions

- **Tailscale.** Embedded via `tsnet`. tailgate joins the tailnet as its own node and serves Funnel itself, with no dependency on a host `tailscaled`. The deployment target is `launchd`.
- **Exposure.** Tailscale Funnel terminates TLS, and the ports it supports constrain `node.port`.
- **Identity.** tsidp is the sole issuer. Funnel strips tailnet identity, so the bearer token is the only identity signal a request carries.
- **MCP auth.** tailgate is an OAuth Resource Server: RFC 9728 metadata, `401` with `WWW-Authenticate` naming the required scopes, and RFC 8707 audience validation. It never forwards a client's token to an upstream.
- **Protocol revisions.** tailgate speaks every revision from `2024-11-05` through `2026-07-28` and chooses per request. It fronts servers and serves clients it does not control, so it can never cut over to a single revision. Every revision difference lives in `internal/protocol`.
- **Routing.** Path prefix `/mcp/<name>`. Each upstream is a distinct protected resource whose audience is its canonical URI, and every resource string in the system comes from `resource.URLs`.
- **Authorization.** Claim-match policy, limited to what introspection returns.
- **Config.** HuJSON. Reload is process restart for now.
- **stdio upstreams.** One child process per MCP session for a stateful caller, one per identity for a stateless one, with a concurrency cap and idle reaping either way.
- **Authorization-server fronting.** tailgate serves RFC 8414 metadata, `/authorize`, and `/token` at its own origin for clients that assume same-origin OAuth instead of following discovery. `/authorize` is a redirect so tsidp sees the authorizing person's tailnet identity, `/token` is a bounded proxy over the tailnet, and `/register` stays absent.
- **Dependencies.** `go.mod` is the list and it stays short: adding one to an internet-facing binary needs a reason. Opaque access tokens mean nothing is verified locally, so no JOSE or JWT library belongs here.

## Settled Contracts

These come from research against pinned sources plus an end-to-end proxy test. Do not relitigate them.

### tsidp, Pinned at `99effa593a177e55f6e8ebd64041c4da602f9807` (2026-07-24)

- **Access tokens are opaque** 32-char random hex held in memory. There is no JWT access token and no RFC 9068 support. Verification is introspection at `/introspect`, discovered via `/.well-known/openid-configuration`.
- **Introspection callers authenticate three ways** (tsidp's `identifyClient`): registered confidential-client credentials, accepted from anywhere including over Funnel, then loopback, then tailnet identity via `WhoIs`. Only the `WhoIs` path is tailnet-gated. tailgate dials through `tsnet.Server.HTTPClient` to take it, which needs no stored secret.
- **The `resource` parameter only works on token and refresh requests.** `/authorize` ignores it, so a client that omits it on the token POST gets a token with no resource audience.
- **`aud` is `[client_id, resource...]`.** tsidp matches requested resources against the app-capability grant exactly, with no canonicalization.
- **Introspection claims are `sub`, `username`, `scope`, and, with the `email` scope, `email`.** A `profile` scope adds `preferred_username` and `picture`. `sub` is the bare decimal user ID, unlike the ID token's `userid:N` form, so policy allowlists must use the bare form. Grant `extraClaims`, including any `groups`, appear only in ID tokens and userinfo, so policy cannot match on them.
- **Clients are confidential.** `/token` requires `client_id` and `client_secret`, so a public PKCE-only client cannot redeem a code. PKCE S256 is supported on top.
- **Tailnet-only endpoints:** `/authorize` (the authorizing browser must be on the tailnet), `/register` (DCR, additionally gated by an `allow_dcr` grant), and the admin UI. Funnel-reachable: `/token`, `/introspect`, `/userinfo`, and the well-known metadata, which omits `registration_endpoint` on Funnel requests.
- **Lifetimes.** Access and ID tokens 5 minutes, refresh tokens 30 days and single-use.

### MCP, Verified Against the Published Specs

Two eras are live at once and tailgate serves both. Everything under "Both Eras" holds whatever revision a request declares.

#### Both Eras

- JSON-RPC batching stays removed. Each POST body is a single request, notification, or response.
- POSTed notifications get `202` with no body. POSTed requests get either one `application/json` object or a `text/event-stream`. What a POSTed response gets diverges by era.
- An invalid `Origin` gets `403`.
- `MCP-Protocol-Version` names the revision. An invalid value gets `400`. A missing header means assume `2025-03-26`, the last revision before the header existed.
- Client ID metadata documents (CIMD) are the preferred registration mechanism and DCR is deprecated as of `2026-07-28`, so tailnet-side pre-registration of confidential clients remains spec-compliant onboarding.

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

The settled contracts describe external systems, not this code, so nothing in the repository will contradict them once they go stale. Re-verify them against the source when the tsidp pin or the MCP revision moves.
