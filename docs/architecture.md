# Architecture

Every request arrives at `internal/router` from the embedded tsnet node's Funnel listener and leaves through a `proxy.Transport`. Each package's doc comment states its own contract. [security.md](security.md) covers the defenses this code enforces.

## Endpoints

The router dispatches in a fixed order, after the origin check:

| Path | Handler |
|---|---|
| `/.well-known/oauth-protected-resource[/mcp/<name>]` | RFC 9728 protected-resource metadata (`internal/resource`) |
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/authorize`, `/token` | Authorization-server facade (`internal/authserver`) |
| `/`, `/favicon.ico` | Root page and icon (`internal/site`) |
| `/mcp/<name>` | The named upstream's transport, behind the full auth pipeline |
| anything else | `404`, logged but not audited, since no authorization decision was made |

`/mcp/<name>` matching is [exact-segment membership](security.md#exact-segment-routing) in the configured upstream set. The metadata handler applies the same rule, so no name can route without addressable metadata.

## Request Pipeline

An `/mcp/<name>` request moves through these gates in order, inside panic recovery:

1. **Origin validation.** A present `Origin` must normalize to the canonical Funnel origin. Denials audit the upstream name only when the path already resolved to a configured one, keeping attacker-chosen path segments out of the audit log.
2. **Authentication.** The bearer token is extracted and verified against the upstream's canonical resource URI.
3. **Authorization.** The policy decision, audited on every allow and deny.
4. **Session claim.** If the caller presented `Mcp-Session-Id` and the transport does not manage its own sessions, the binding table checks it.
5. **Body limit.** The body is buffered rather than wrapped, so an overflow answers `413` instead of surfacing mid-stream. Running after authorization keeps auth decisions independent of the body.
6. **Protocol checks.** The revision is parsed from `MCP-Protocol-Version` and, for the header-mirroring era, the mirrored headers are validated against the body. This runs last so an unauthenticated caller learns nothing about the upstream's protocol shape from a mismatch refusal.
7. **Dispatch.** The request is cloned with the identity injected into context, credentials stripped, and `URL.Path` reset to `/`. The upstream never sees the `/mcp/<name>` prefix.

## Token Verification

`auth.NewVerifier` discovers tsidp's introspection endpoint from `/.well-known/openid-configuration` and [pins it to the issuer's origin](security.md#trust-boundaries). It dials through the tsnet node's HTTP client, which lets tsidp authenticate tailgate by tailnet node identity with no stored secret.

`Verify` rejects anything outside the [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) token grammar before contacting tsidp, serves positive and negative results from separate caches, collapses concurrent lookups of one token into a single introspection call, and gates introspection at 64 concurrent calls.

The authorizer walks the upstream's rules in configured order and the first matching `allow` entry wins. Conditions within an entry are conjunctive.

## Authorization-Server Facade

Some clients, claude.ai among them, never read the RFC 9728 discovery document and assume the authorization server shares the MCP server's origin. `internal/authserver` serves those endpoints at tailgate's own origin, and the protected-resource metadata points spec-following clients at the same place, since tsidp's own `/authorize` refuses requests over Funnel.

- `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` serve the same [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) document, since clients probe either name. It advertises tailgate's own `/authorize` and `/token`, S256 PKCE, and resource indicators.
- `/authorize` is a `302` to tsidp with the query preserved. It cannot be a proxy: tsidp identifies the authorizing person by the connection's tailnet identity, which proxying would replace with tailgate's own.
- `/token` is a bounded reverse proxy over the tailnet.
- `/register` is absent. tsidp resolves its app-capability grant from the caller's tailnet identity, so a proxied registration would arrive as tailgate's node and couple serving any traffic to an `allow_dcr` grant on it. Clients register tailnet-side instead.

## `proxy.Transport`

`proxy.Transport` is `http.Handler` plus `Shutdown` and `Close`. HTTP itself is the contract, carrying JSON bodies, SSE streams, session headers, and resumption without a bespoke message layer. A transport receives only authorized requests, already stripped and rewritten by the router, and owns its own timeout policy, since only it knows whether a response is a bounded JSON object or a stream that must stay open.

`internal/proxy` holds what both transports share. `StatusOf` maps the sentinel errors to statuses: unknown upstream and unknown session to `404`, which is the MCP signal to re-initialize, a caller at its child cap to `429`, an unreachable upstream to `502`, one that timed out to `504`, a draining transport to `503`, and anything unrecognized to `500`, since an unclassified failure must never pass as success. `Drain` is the shutdown sequence both transports embed: `Shutdown` stops accepting work and waits out in-flight requests, `Close` cancels whatever remains. `StripCredentials` implements the [credential strip](security.md#credential-stripping).

## HTTP Transport

`httptransport` wraps `httputil.ReverseProxy`. Construction never dials, so an unreachable upstream shows up per request as `502`. Compression is disabled and every write is flushed immediately, keeping SSE bytes intact and prompt. The rewrite pins the outbound path to exactly the configured target path, since URL joining would turn `/mcp` into `/mcp/` and exact-path upstreams reject that.

Each exchange gets a one-minute timeout, canceled the moment a response's `Content-Type` confirms `text/event-stream`.

## stdio Transport

`stdiotransport` implements the server side of streamable HTTP over a child process. Which lifecycle a caller gets depends on its era.

A caller's JSON-RPC ID never reaches the child. The transport substitutes a monotonic ID of its own on the way in and restores the caller's on the way out, whichever era the caller speaks. Independent POSTs from one caller may each call themselves request `1`, and a caller that hangs up mid-request and retries reuses an ID the child is still working on. Correlating on the caller's ID would let either request take the other's answer.

A notification is the one caller message that reaches the child unmodified, because it is the one carrying no usable ID. tailgate drops a child's server-initiated requests, so a client is never handed anything to answer. A POSTed response therefore answers nothing tailgate carried.

What such a response gets back differs by era. The stateful revisions make one legal, so it gets the `202` they specify. The stateless revision left no server-initiated request to answer, so there it is a `400`. Neither era forwards it to the child, since a caller-chosen ID in the minted namespace would let the child's answer satisfy the wrong request. A message carrying neither a method nor an ID is a `400` on both, because it names nothing to dispatch and nothing to answer.

### Stateful Sessions

A caller on a revision through 2025-11-25 gets one child per session. `initialize` reserves a cap slot, mints a cryptographically random session ID, spawns the child, and runs the handshake. The session ID is bound to both the child and the identity that created it, and `DELETE` terminates the session.

### Stateless Children

A caller on 2026-07-28 gets one child per identity, shared across its concurrent requests. The first request spawns it while concurrent arrivals wait on the same ready signal rather than each spawning a process. The transport settles the child's era with a `server/discover` probe:

- An answer means the child speaks the revision.
- An error in the MCP-reserved `-32020` to `-32099` range means it speaks the revision and declined, which fails the child as unavailable.
- Any other error means a legacy child, for which tailgate runs the `initialize` handshake itself.

`subscriptions/listen` is the one response held open and the one exempt from the exchange timeout. A listener registers before the request is sent so no notification is lost in the gap, notifications flow as SSE frames with a comment keep-alive every thirty seconds, and the child's eventual JSON-RPC response to the listen request ends the stream. A listener that falls behind is closed rather than allowed to block the child's single reader.

### Concurrency and Reaping

The concurrency cap is per identity per upstream, defaults to 4, and counts live processes: a slot releases only when the child has exited. A reaper terminates sessions idle past the configured timeout, defaulting to five minutes.

### Child Processes

Children inherit tailgate's environment minus `TS_AUTHKEY` and `TS_AUTH_KEY`, plus whatever the upstream's config adds. Termination closes stdin, gives the child two seconds to exit itself, then kills its whole process group, so wrappers like `npx` and `uv` do not orphan the real server. A child whose stdout framing breaks, or that stops reading stdin, is torn down immediately, since nothing it says afterward can be trusted to be a whole message.

## Session Binding

HTTP upstreams mint their own session IDs, opaque to tailgate, so the router keeps a binding table for them. A binding is recorded only when the upstream answers with a 2xx, and released when a `DELETE` succeeds or the upstream answers `404`. The table holds 4,096 entries with a one-hour TTL refreshed on use. Eviction takes from the subject holding the most bindings first, so a caller minting sessions in a loop pushes out its own rather than another caller's live ones, and a binding in use by a request or stream never expires mid-response.

## Protocol Revisions

`internal/protocol` is the single place that knows which revision has what. `Parse` resolves `MCP-Protocol-Version`: an absent header means 2025-03-26, the last revision before the header existed, and an unrecognized value is refused with the supported list attached. A duplicated header is refused before parsing, since a caller could otherwise name one revision to tailgate while an upstream reads the other copy.

For the header-mirroring era, `ValidateMirrored` parses the JSON-RPC envelope and requires `Mcp-Method` to equal the body's method, the header and `_meta` protocol versions to agree, and `Mcp-Name` (decoded through the `=?base64?…?=` sentinel) to equal the named tool, prompt, or resource. Disagreement is a `400` with JSON-RPC code `-32020`, naming the offending header but not the caller-supplied value. `Mcp-Param-*` headers are forwarded untouched, since only a server that knows the tool's schema can judge them. A notification that carries no mirrored headers is left alone.

## Startup and Shutdown

`main` runs a forced sequence: load config, join the tailnet, seed resource URLs from the joined FQDN, build the verifier on the tsnet HTTP client, assemble the router, then serve Funnel. Nothing serves until every step succeeds.

The join is bounded, because tsnet reprints a login URL forever for a node that cannot authenticate and an unbounded wait under launchd looks healthy while serving nothing. [deploying.md](deploying.md#startup-failures) covers the windows and the other startup checks.

Shutdown stops accepting connections, drains transports for up to 30 seconds so in-flight requests and open streams finish, gives remaining HTTP connections 10 more seconds, hard-closes what is left, then leaves the tailnet. The stdio transport's `Close` inverts the order and kills children first, since a request blocked on a child is released by that child's death.
