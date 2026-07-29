# tailgate Build Guide

tailgate is a single Go binary that fronts MCP servers behind Tailscale Funnel, validates tsidp OIDC tokens, and proxies authorized requests to HTTP or stdio MCP upstreams. `README.md` is the human overview. This file is the build contract for agents working in the repo.

## Locked Decisions

- **Language.** Go, single binary, run under `launchd`.
- **Tailscale.** Embedded via `tsnet`. tailgate joins the tailnet as its own node and serves Funnel itself. No dependency on a host `tailscaled`.
- **Exposure.** Tailscale Funnel. Tailscale terminates TLS. Funnel supports TCP ports 443, 8443, and 10000 only.
- **Identity.** tsidp is the issuer. Its access tokens are opaque, so validation is RFC 7662 introspection against tsidp over the tailnet. Funnel strips tailnet identity, so the bearer token is the only identity signal.
- **MCP auth.** tailgate is a spec-compliant OAuth Resource Server. It serves `/.well-known/oauth-protected-resource`, answers `401` with `WWW-Authenticate` naming the required scopes, and validates token audience per RFC 8707. It never forwards the client's token to an upstream.
- **Protocol revisions.** tailgate speaks every revision from `2024-11-05` through `2026-07-28`, choosing per request from `MCP-Protocol-Version`. It fronts servers and serves clients it does not control, so it can never cut over to a single revision. `internal/protocol` is the single place that knows which revision has what.
- **Routing.** Path prefix `/mcp/<name>`. Each upstream is a distinct protected resource with its own audience, which is its canonical URI.
- **Authorization.** Claim-match policy. `auth.Identity` carries `sub`, `email`, and the full claim set from introspection. Config ships with email and sub allowlists.
- **Config.** HuJSON, a list of upstreams plus policy. Reload is process restart for now.
- **stdio upstreams.** One child process per MCP session for a stateful caller, one per identity for a stateless one, with a concurrency cap and idle reaping either way.
- **Audit.** Every allow and deny decision is logged with identity, upstream, and outcome via `log/slog`.

## Dependencies

- `tailscale.com` for the `tsnet` embedded node and Funnel listener.
- `github.com/tailscale/hujson` for config parsing.
- `github.com/google/go-cmp` for test assertions.

Everything else is standard library: `net/http/httputil` for HTTP proxying, `net/http` for the introspection client, `os/exec` for stdio supervision, `log/slog` for audit. The contract spike removed `go-oidc` and `go-jose`: with opaque access tokens there is no JWT to verify locally.

## Settled Contracts

These facts come from research against pinned sources plus an end-to-end proxy test. Do not relitigate them. Re-verify them when the tsidp pin moves or the MCP revision changes.

### tsidp, Pinned at `99effa593a177e55f6e8ebd64041c4da602f9807` (2026-07-24)

- **Access tokens are opaque** 32-char random hex, stored in memory. There is no JWT access token and no RFC 9068 support. Verification is introspection at `/introspect`, discovered via `/.well-known/openid-configuration`. A tsidp restart invalidates every outstanding token.
- **Introspection callers authenticate three ways** (tsidp's `identifyClient`): registered confidential-client credentials, accepted from anywhere including over Funnel, then loopback, then tailnet identity via `WhoIs`. Only the `WhoIs` path is tailnet-gated, and introspection is not scoped to the caller's own tokens, so a leaked client secret lets its holder introspect any outstanding token from the public internet. tailgate dials through tsnet (`tsnet.Server.HTTPClient`) to use the `WhoIs` path, which needs no stored secret.
- **The `resource` parameter only works on token and refresh requests.** `/authorize` ignores it. MCP clients must send `resource` on the token POST or the token carries no resource audience.
- **`aud` is `[client_id, resource...]`** and tsidp matches requested resources against the app-capability grant byte-for-byte, with no canonicalization. Every resource string in the system must come from `resource.URLs`.
- **Introspection claims are `sub`, `username`, `scope`, and (with the `email` scope) `email`.** A `profile` scope adds `preferred_username` and `picture`. `sub` is the bare decimal user ID, unlike the ID token's `userid:N` form. Policy allowlists must use the bare form. Grant `extraClaims` (including any `groups`) appear only in ID tokens and userinfo, never in introspection, so policy cannot match on them yet.
- **Clients are confidential.** `/token` requires `client_id` and `client_secret`. A public PKCE-only client cannot redeem a code. PKCE S256 is supported on top.
- **Tailnet-only endpoints:** `/authorize` (the authorizing browser must be on the tailnet), `/register` (DCR, additionally gated by an `allow_dcr` grant), and the admin UI. Funnel-reachable: `/token`, `/introspect`, `/userinfo`, and the well-known metadata, which correctly omits `registration_endpoint` on Funnel requests.
- **Lifetimes.** Access and ID tokens 5 minutes, refresh tokens 30 days and single-use. Caching introspection results until `exp` is bounded by the 5-minute lifetime, which is also the staleness window: deleting a client revokes its outstanding tokens immediately, and a cached allow can outlive that by up to the remaining lifetime.

### MCP, Verified Against the Published Specs

Two eras are live at once, and tailgate serves both. Everything under "Both Eras" holds whatever revision a request declares.

#### Both Eras

- JSON-RPC batching stays removed. Each POST body is a single request, notification, or response.
- POSTed notifications get `202` with no body. POSTed requests get either one `application/json` object or a `text/event-stream`. What a POSTed response gets diverges by era, so each section below says.
- An invalid `Origin` gets `403`.
- `MCP-Protocol-Version` names the revision. An invalid value gets `400`. A missing header means assume `2025-03-26`, the last revision before the header existed.
- Client ID metadata documents (CIMD) are the preferred registration mechanism and DCR is deprecated as of `2026-07-28`, so tailnet-side pre-registration of confidential clients remains spec-compliant onboarding.

#### 2024-11-05 Through 2025-11-25 (Stateful)

- A POSTed response gets `202` with no body, like a notification: these revisions let a server open a request of its own, so a client has something to answer.
- The server mints `Mcp-Session-Id` on the initialize response. Requests missing a required session header get `400`. An unknown or expired session gets `404`, which is what tells the client to re-initialize. `DELETE` terminates a session and may be refused with `405`.
- The standalone `GET` SSE stream may be refused with `405`. Resumption is always `GET` with `Last-Event-ID`, and replay is per stream, never across streams. Servers may close an SSE connection without terminating the stream (polling), so a proxy must pass `id` and `retry` fields through byte-for-byte and must not treat connection close as stream end.
- Session IDs must be cryptographically random visible ASCII, must never serve as authentication, and should be bound to the authenticated identity.

#### 2026-07-28 (Stateless)

- Protocol-level sessions and the `initialize` handshake are gone. Every request carries its own protocol version and client capabilities in `params._meta` under `io.modelcontextprotocol/*` keys. `Mcp-Session-Id` and `Last-Event-ID` are ignored, and `GET` and `DELETE` at the MCP endpoint get `405`. Cross-call state is a server-minted handle passed as an ordinary tool argument.
- Selected body fields are mirrored into HTTP headers so intermediaries can route without parsing bodies. `Mcp-Method` is required on every request, and `Mcp-Name` on `tools/call`, `prompts/get`, and `resources/read`. A value that cannot be plain ASCII is wrapped in the `=?base64?…?=` sentinel. Servers that read the body **MUST** reject a header that disagrees with it, with `400` and JSON-RPC code `-32020`.
- `Mcp-Param-{Name}` headers mirror tool arguments annotated with `x-mcp-header` in the tool's `inputSchema`. An intermediary that does not recognize one **MUST** forward it and otherwise ignore it. tailgate never sees an `inputSchema`, so every one of these is unrecognized to it.
- The standalone `GET` stream and `resources/subscribe` are replaced by `subscriptions/listen`, a POST whose response stream stays open. Anything that assumes a POST response completes promptly breaks on it. The server acknowledges with `notifications/subscriptions/acknowledged` as the first message on the stream, which is what opens the subscription. The JSON-RPC response to the listen request is what ends it, so a subscription that runs indefinitely never produces one. Servers should emit an SSE comment line as a keep-alive and set `X-Accel-Buffering: no`. There is no resumption, so a broken stream loses its request and the client reissues.
- `server/discover` is mandatory for servers, and the spec names it the backward-compatibility probe on stdio. The probe carries the caller's version and capabilities in `params._meta`, and a server that implements the method answers a probe without them as though the method itself were unknown. A child that answers it is of this era. The fallback **MUST NOT** be keyed to one error code: a legacy child has no notion of the method and refuses however its runtime does, and the SDKs disagree (`-32601` on TypeScript, `-32602` on Python, a code JSON-RPC does not define on Go). Only a code from the `-32020` to `-32099` range the spec reserves for itself identifies a child that implements the revision and still declined.
- Server-initiated JSON-RPC requests are gone. Sampling, elicitation, and roots now arrive as an `InputRequiredResult`, and the client answers by retrying the original request with the input supplied. Every result carries a `resultType`. With no server-initiated request left to answer, a POSTed response is invalid input rather than a `202`.
- A `400` whose body is not a recognized JSON-RPC error tells a probing client the server is of the older era. An intermediary that refuses a modern request with bare text therefore talks its callers into downgrading.
- Servers **SHOULD** put a `scope` parameter on the `WWW-Authenticate` challenge, and answer an insufficiently scoped token with `403` and `error="insufficient_scope"`.
- Roots, sampling, and logging are deprecated with a twelve-month window. `ping`, `logging/setLevel`, and `tasks/list` are removed. Tasks moved to an official extension.

## Packages

`main` joins the tailnet, seeds `resource.URLs` from the node's FQDN, builds the verifier on the tsnet HTTP client, assembles the router, serves Funnel, and drains on signal. The order is forced: nothing serves until every step succeeds.

- `internal/config`: schema and loader. Policy `Match` fields are limited to what introspection returns.
- `internal/protocol`: the revisions tailgate speaks and what each one puts on the wire. `Parse` resolves `MCP-Protocol-Version`, `Stateless` and `MirrorsHeaders` are the era predicates every other package branches on, and `ValidateMirrored` is the intermediary half of the header contract. `WriteError` answers refusals in JSON-RPC, which is what keeps a modern client from reading a `400` as a reason to downgrade.
- `internal/resource`: `URLs` is the single canonicalization point, seeded from the tailnet FQDN after join. `ResourceURL(name)` output is the byte-exact string used in the client `resource` param, the tsidp grant, the `aud` check, and each metadata doc. `Handler` serves the RFC 9728 well-known subtree.
- `internal/auth`: `Identity` and `Decision`, the introspection `Verifier`, the policy `Authorizer`, and identity-in-context helpers for transports and audit.
- `internal/grant`: builds the `tailscale.com/cap/tsidp` grant from `resource.URLs`, so the resource strings in the tailnet policy come from the same place as the audience tailgate validates. Surfaced as `tailgate grant`. Generating it offline needs `node.tailnet`, which `serve` also checks against the FQDN the join reports.
- `internal/proxy`: the `Transport` seam is `http.Handler` plus `Shutdown` and `Close`. HTTP semantics are the contract. The seam carries JSON and SSE responses, session headers, and resumption without a bespoke message layer. Sentinel errors plus `StatusOf` are the shared error taxonomy, and `Drain` is the shared refuse-and-wait choreography. The package doc records the lifecycle and drain contract.
- `internal/proxy/httptransport`: the reverse proxy for HTTP upstreams.
- `internal/proxy/stdiotransport`: the server side of streamable HTTP over a child process, with JSON-RPC correlation, a per-identity-per-upstream cap, and idle reaping. A stateful caller gets a child per session with the session id bound to it. A stateless caller gets a child per identity, whose era the transport settles with `server/discover` and whose `initialize` handshake it runs itself when the child predates the revision. Caller JSON-RPC ids are substituted for minted ones on that path, since independent POSTs collide, and a message carrying an id but no method is refused, since forwarding it would put a caller-chosen id into that minted namespace. `subscriptions/listen` is the one response held open, so it is the one exempt from the exchange timeout: the stream opens as soon as the request goes out, and the child's eventual response to it closes the stream.
- `internal/router`: the public handler. Exact-segment routing, auth ahead of every transport, session binding, `Origin` validation, body limits, mirrored-header validation, header stripping, identity injection, and panic recovery.
- `internal/tsnetserver`: the embedded node, the `FQDN` that seeds `resource.URLs`, and the Funnel listener.
- `internal/audit`: structured decision log.

## Provisioning (Tailnet-Side, Outside the Binary)

- Grant the `funnel` node attribute to tailgate's node.
- Configure the tsidp app-capability grant (`tailscale.com/cap/tsidp`) to authorize each upstream's resource URI. Grant strings must byte-match `ResourceURL` output.
- Register each MCP client as a confidential client (tailnet-side, since DCR and the admin UI are tailnet-only) and instruct it to send `resource` on the token request.
- Clients must request the `email` scope: introspection omits `email` without it, and the shipped email-allowlist policy then denies every request from that client. The `401` challenge and the metadata document both name the scope, so a client that reads either discovers this without being told.

## Conventions

- No numbered phases or steps in code or names. Use descriptive functions called in sequence.
- Avoid catch-all packages. Keep each package well scoped.
- Fail closed. Any validation or authorization error denies the request.
- Log every authorization decision.

## Security Invariants

tailgate is an internet-facing boundary where a validation gap is a remote exploit. Every request path holds these:

- **Fail closed.** Any verify, discovery, introspection, or authorization error denies the request. A verifier-construction failure means the upstream is unavailable, never a passthrough. An introspection transport failure is a 503, never a 401 challenge and never an allow.
- **No token passthrough.** Strip the client `Authorization` header before forwarding to any upstream. `httputil.ReverseProxy` forwards inbound headers by default. Strip inbound `X-Forwarded-*` and any identity header tailgate sets itself. The router strips, and `httptransport` strips again so the invariant survives caller mistakes.
- **Exact-segment routing.** Decode and clean the path, then match the `/mcp/<name>` segment as exact membership in the configured upstream set. Reject `/mcp//x`, `/mcp/x/../y`, and `%2e%2e`. Route `/.well-known/oauth-protected-resource/mcp/<name>` to metadata rather than to the upstream.
- **Auth precedes spawn.** Token verify and the authz decision gate session creation. A stdio child is never spawned before authorization. The concurrency cap is per-identity-per-upstream, not global, so one caller cannot starve others.
- **Recover middleware.** A panic in the request path returns 500 and never proceeds to an upstream.
- **Origin validation.** Validate `Origin` against DNS rebinding, since tailgate is internet-facing via Funnel. Invalid origins get 403.
- **Timeouts.** Set `ReadHeaderTimeout` against Slowloris and `MaxBytesReader` on POST bodies. Exempt SSE streams from the request timeout, which is why timeout policy lives on the seam. A blanket `http.Server` setting cannot exempt one response and bound the next.
- **Header and body agree.** Where a revision mirrors body fields into headers, refuse a request whose pair disagree. tailgate is the intermediary those rules exist to constrain: routing on the header while the upstream executes on the body is how one request becomes two. The revision is resolved from a header that appears exactly once, since reading the first of several would let a caller name a revision with no mirroring rules while the upstream reads the last and executes under them. A POST is held to the contract whether or not it carried a body, since an empty one backs no header either.
- **Session binding follows the header.** Bind any `Mcp-Session-Id` a caller presents, whatever revision the request declares. Gating the binding on the declared revision would let a caller shed it by claiming the revision that dropped the header, and for a stdio upstream the transport's own refusal is the only record of a session probe, since the router delegates binding to it.
- **Refusals stay in JSON-RPC.** A `400` whose body is not a recognized JSON-RPC error is what tells a client probing for the server's era that it predates the stateless revision, so every refusal tailgate originates at that status answers in the modern shape. Bare text talks callers into downgrading.

## Curation

The settled-contracts section records pinned external research about tsidp and the MCP spec. It describes neither this code nor its intent. It stays until tsidp or the MCP revision moves, at which point re-verify it rather than trusting it.
