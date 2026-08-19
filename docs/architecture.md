# Architecture

This document maps tailgate's internals for anyone changing the code or operating it in anger. The [README](../README.md) covers what tailgate is and how to deploy it. [security.md](security.md) covers the threat model the pieces below enforce.

## Packages

| Package | Role |
|---|---|
| `internal/config` | HuJSON schema, loading, and validation. Unknown fields are load errors. |
| `internal/protocol` | The MCP revision model, header/body mirroring validation, and JSON-RPC error responses. |
| `internal/resource` | Canonical resource URIs, RFC 9728 metadata, and the `WWW-Authenticate` challenge builder. |
| `internal/auth` | `Identity` and `Decision`, the introspection verifier with caching, and the claim-match authorizer. |
| `internal/authserver` | The authorization-server facade at tailgate's own origin: `/authorize`, `/token`, and RFC 8414 metadata. |
| `internal/grant` | Builds the `tailscale.com/cap/tsidp` app-capability grant from configured upstreams. |
| `internal/proxy` | The shared `Transport` seam: error taxonomy, drain choreography, and credential stripping. |
| `internal/proxy/httptransport` | Reverse proxy for HTTP upstreams, SSE-aware, with a bounded exchange timeout. |
| `internal/proxy/stdiotransport` | The server side of streamable HTTP over a child process, with JSON-RPC correlation. |
| `internal/router` | The internet-facing handler: routing, auth, session binding, protocol checks, and dispatch. |
| `internal/site` | The unauthenticated root page and configured favicon for icon crawlers. |
| `internal/tsnetserver` | The embedded tsnet node, the tailnet join, the Funnel listener, and the tailnet-dialing HTTP client. |
| `internal/audit` | Structured authorization-decision logging. |

## Endpoints

The router dispatches in a fixed order, and the origin check in the next section runs before any of it:

| Path | Handler |
|---|---|
| `/.well-known/oauth-protected-resource[/mcp/<name>]` | RFC 9728 protected-resource metadata (`internal/resource`) |
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/authorize`, `/token` | Authorization-server facade (`internal/authserver`) |
| `/`, `/favicon.ico` | Root page and icon (`internal/site`) |
| `/mcp/<name>` | The named upstream's transport, behind the full auth pipeline |
| anything else | `404`, logged but not audited, since no authorization decision was made |

Path matching for `/mcp/<name>` is exact-segment membership in the configured upstream set. Percent-encoded and non-clean paths are rejected outright. `/mcp/x/../y` and `%2e%2e` never alias a real route, and the metadata handler applies the same rule so no name can route without addressable metadata.

## Request Pipeline

An `/mcp/<name>` request moves through these gates in order, inside panic recovery that turns any request-path panic into a `500` before it can reach an upstream:

1. **Origin validation.** A present `Origin` header must normalize to the canonical Funnel origin, defending against DNS rebinding. A request without the header is allowed through, since non-browser MCP clients send none and there is nothing to rebind. Normalization lowercases, strips default ports, and rejects anything with a path, query, opaque `null`, or a scheme other than `http`/`https`. Denials audit the upstream name only when the path already resolved to a configured one, keeping attacker-chosen path segments out of the audit log.
2. **Authentication.** The bearer token is extracted (a duplicated `Authorization` header is malformed, since downstream proxies could disagree about which copy wins) and verified against the upstream's canonical resource URI. Missing or invalid tokens get a `401` whose `WWW-Authenticate` challenge names the metadata URL and scopes. A verifier transport failure is a `503`, never a challenge and never an allow.
3. **Authorization.** The policy decision, audited on every allow and deny.
4. **Session claim.** If the caller presented `Mcp-Session-Id` and the transport does not manage its own sessions, the binding table checks it (see below).
5. **Body limit.** The body is buffered up to the limit so an overflow answers `413` cleanly rather than surfacing mid-stream to the upstream. Running after authorization keeps auth decisions independent of the body.
6. **Protocol checks.** The revision is parsed from `MCP-Protocol-Version` and, for the header-mirroring era, the mirrored headers are validated against the body. This runs last so an unauthenticated caller learns nothing about the upstream's protocol shape from a mismatch refusal.
7. **Dispatch.** The request is cloned with the identity injected into context, credentials stripped, and `URL.Path` reset to `/`. The upstream never sees the `/mcp/<name>` prefix.

## Token Verification

`auth.NewVerifier` discovers tsidp's introspection endpoint from `/.well-known/openid-configuration`, requiring the returned issuer to equal the configured one and the introspection endpoint to stay on the issuer's origin. A tampered discovery document cannot exfiltrate tokens. The verifier dials through the tsnet node's HTTP client, which lets tsidp authenticate tailgate by tailnet node identity with no stored secret.

Verification is layered to keep introspection cheap and every check live:

- A syntax pre-check rejects anything outside the RFC 6750 token grammar before contacting tsidp.
- Positive results cache until the token's own `exp`, capped at five minutes. Negative results cache for thirty seconds, a deliberately shorter window since those entries are keyed by attacker-chosen strings. Cache keys are SHA-256 digests, never the bearer itself.
- Concurrent lookups of the same token collapse into a single introspection call, and an overall concurrency gate of 64 sheds excess load as `503` rather than queuing.
- `exp`, `nbf`, byte-exact `aud` membership, and a non-empty `sub` are re-checked on every call, including cache hits. A cached allow can never widen scope.

The authorizer walks the upstream's rules in configured order and the first matching `allow` entry wins. Conditions within an entry are conjunctive, and a condition that cannot be evaluated (an absent email claim, a non-string value, an empty claim name) denies rather than being skipped. An upstream with no rules denies everyone.

## Authorization-Server Facade

Some clients, claude.ai among them, never read the RFC 9728 discovery document and assume the authorization server shares the MCP server's origin. The facade meets them there, and the protected-resource metadata points spec-following clients at the same place, since tsidp's real `/authorize` refuses requests arriving over Funnel.

- `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` serve the same RFC 8414 document, since clients probe either name. It advertises tailgate's own `/authorize` and `/token`, S256 PKCE, and resource indicators.
- `/authorize` is a `302` redirect to tsidp with the query preserved byte-for-byte. It cannot be a proxy: tsidp identifies the authorizing person by the connection's tailnet identity, which proxying would replace with tailgate's own.
- `/token` is a true reverse proxy over the tailnet, bounded to 64 KiB in each direction, forwarding only `Authorization`, `Content-Type`, and `Accept`. Client credentials transit it and are never logged.
- `/register` is deliberately absent. tsidp resolves its app-capability grant from the caller's tailnet identity. Proxied registrations would arrive as tailgate's node and couple serving any traffic to an `allow_dcr` grant on that node. Clients are registered tailnet-side instead.

## The Transport Seam

`proxy.Transport` is `http.Handler` plus `Shutdown` and `Close`. HTTP itself is the seam contract: expressing a transport as a handler carries JSON bodies, SSE streams, session headers, and resumption without a bespoke message layer. A transport receives only authorized requests, already stripped and rewritten by the router, and owns its own timeout policy, since only the transport knows whether a response is a bounded JSON object or an SSE stream that must stay open.

Shared machinery on the seam:

- **Error taxonomy.** Sentinel errors map to statuses via `StatusOf`: unknown upstream and unknown session to `404` (the MCP signal to re-initialize), cap exceeded to `429`, upstream unavailable to `502`, upstream timeout to `504`, draining to `503`, and anything unrecognized to `500`, since an unclassified failure must never pass as success.
- **Drain.** A shared refuse-and-wait choreography both transports embed. `Shutdown` stops accepting work and waits out in-flight requests. `Close` cancels whatever remains.
- **Credential stripping.** `StripCredentials` removes `Authorization`, `Proxy-Authorization`, `Forwarded`, and everything prefixed `X-Forwarded-` or `X-Tailgate-`. The router strips before dispatch and each transport strips again. The no-passthrough invariant survives caller mistakes.

## HTTP Transport

`httptransport` wraps `httputil.ReverseProxy`. Construction never dials. An unreachable upstream shows up per-request as `502`. Compression is disabled and every write is flushed immediately, keeping SSE bytes intact and prompt. The rewrite pins the outbound path to exactly the configured target path, since URL joining would turn `/mcp` into `/mcp/` and exact-path upstreams reject that.

Each exchange gets a one-minute timeout that is canceled the moment a response's `Content-Type` confirms `text/event-stream`. The exemption is per-response-type-detected: a slow upstream can still time out before its headers arrive, and only a confirmed SSE response becomes unbounded.

## stdio Transport

`stdiotransport` implements the server side of streamable HTTP over a child process. Which lifecycle a caller gets depends on its era.

#### Stateful Sessions

A caller on a revision through 2025-11-25 gets one child per session. `initialize` reserves a cap slot, mints a cryptographically random session ID, spawns the child, and runs the handshake. The session ID is bound to both the child and the identity that created it. A request presenting a session bound to a different identity gets the same `404` as an unknown session, confirming nothing to a hijacker. `DELETE` terminates the session. The binding check applies to whatever session header is presented, regardless of the revision the request declares. A caller cannot shed it by claiming the stateless revision.

#### Stateless Children

A caller on 2026-07-28 gets one child per identity, shared across its concurrent requests. The first request spawns the child while concurrent arrivals wait on the same ready signal rather than each spawning a process. The transport settles the child's era with a `server/discover` probe: an answer means the child speaks the revision, an error in the MCP-reserved `-32020` to `-32099` range means it speaks the revision and refused, and any other error means a legacy child, for which tailgate runs the `initialize` handshake itself. The fallback is deliberately not keyed to one error code, because legacy SDKs disagree on what they return.

Because independent POSTs from one caller may each call themselves request `1`, the transport substitutes its own monotonic JSON-RPC IDs on the way in and restores the caller's on the way out. A message carrying an ID but no method is refused rather than forwarded, since forwarding would inject a caller-chosen ID into the minted namespace and let a child's answer satisfy the wrong request.

`subscriptions/listen` is the one response held open and the one exempt from the exchange timeout. A listener registers before the request is sent so no notification is lost in the gap, notifications flow as SSE frames with a comment keep-alive every thirty seconds, and the child's eventual JSON-RPC response to the listen request is what ends the stream. A listener that falls behind is closed rather than allowed to block the child's single reader.

#### Caps, Reaping, and the Child Environment

The concurrency cap is per identity per upstream, defaulting to 4, and counts live processes: a slot releases only when the child has actually exited. Looping initialize and delete cannot hold processes past the cap. A reaper terminates sessions idle past the configured timeout, defaulting to five minutes. Children inherit tailgate's environment minus `TS_AUTHKEY` and `TS_AUTH_KEY`, since a stdio upstream is third-party code that must never see the credential that joins the tailnet, plus whatever the upstream's config adds.

Termination closes stdin, gives the child two seconds to exit itself, then kills its whole process group. Wrappers like `npx` and `uv` do not orphan the real server. A child whose stdout framing breaks, or that stops reading stdin, is torn down immediately, since nothing it says afterward can be trusted to be a whole message.

## Session Binding

For HTTP upstreams, whose sessions are minted by the upstream and opaque to tailgate, the router keeps its own binding table. A binding is recorded only when the upstream answers a session-minting request with a 2xx, and only session IDs the router itself recorded can ever be claimed. The table is bounded (4,096 entries, one-hour TTL from last release), and eviction targets the subject holding the most bindings first. One caller's churn cannot evict another's live sessions. A binding actively in use by a request or stream never expires mid-response. Unknown session and foreign session return an identical `404`, which both resists probing and doubles as the MCP re-initialize signal after a tailgate restart drops the in-memory table.

## Protocol Revisions

`internal/protocol` is the single place that knows which revision has what. `Parse` resolves `MCP-Protocol-Version`: an absent header means 2025-03-26, the last revision before the header existed, and an unrecognized value is refused with the supported list attached. A duplicated header is refused before parsing, since a caller could otherwise name one revision to tailgate while an upstream reads the other copy.

For the header-mirroring era, `ValidateMirrored` parses the JSON-RPC envelope and requires `Mcp-Method` to equal the body's method, the header and `_meta` protocol versions to agree, and `Mcp-Name` (decoded through the `=?base64?…?=` sentinel) to equal the named tool, prompt, or resource. Disagreement is a `400` with JSON-RPC code `-32020`, naming the offending header but not the caller-supplied value. `Mcp-Param-*` headers are forwarded untouched, since only a server that knows the tool's schema can judge them. Notifications skip the checks entirely, since they carry no mirrored headers.

Every refusal the package writes is a JSON-RPC error object, because a `400` with an unrecognized body is the downgrade signal to a probing client.

## Startup and Shutdown

`main` runs a forced sequence: load config, join the tailnet, seed resource URLs from the joined FQDN, build the verifier on the tsnet HTTP client, assemble the router, then serve Funnel. Nothing serves until every step succeeds.

The join is bounded at 90 seconds unattended, or five minutes with `-open-login`, since a node that cannot authenticate makes tsnet reprint a login URL forever, and an unbounded wait under launchd looks healthy while serving nothing. When `node.tailnet` is set, the joined FQDN must match the configured one, catching a control server that hands back a suffixed hostname before every resource URI silently drifts from the grant.

Shutdown stops accepting connections, drains transports for up to 30 seconds so in-flight requests and open streams finish, gives remaining HTTP connections 10 more seconds, hard-closes whatever is left, then leaves the tailnet. The stdio transport's `Close` inverts the order and kills children first, since a request blocked on a child is released by that child's death.
