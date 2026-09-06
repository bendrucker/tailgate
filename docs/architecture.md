# Architecture

Every request arrives at `internal/router` from the embedded tsnet node's Funnel listener and leaves through a `proxy.Transport`. Each package's doc comment states its own contract. [security.md](security.md) covers the defenses this code enforces.

## Endpoints

The router dispatches in a fixed order, after the origin check:

| Path | Handler |
|---|---|
| `/.well-known/oauth-protected-resource[/mcp/<name>]` | RFC 9728 protected-resource metadata (`internal/resource`) |
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/authorize`, `/token` | Authorization server (`internal/authserver`) |
| `/`, `/favicon.ico` | Root page and icon (`internal/site`) |
| `/mcp/<name>` | The named upstream's transport, behind the full auth pipeline |
| anything else | `404`, logged but not audited, since no authorization decision was made |

`/mcp/<name>` matching is [exact-segment membership](security.md#exact-segment-routing) in the configured upstream set. The metadata handler applies the same rule, so no name can route without addressable metadata.

## Request Pipeline

Panic recovery is outermost. Inside it the origin check runs, then routing. Origin validation guards every path tailgate serves rather than upstreams alone, which is why it sits ahead of routing rather than in the pipeline: a present `Origin` must normalize to the canonical Funnel origin, and denials audit the upstream name only when the path already resolved to a configured one, keeping attacker-chosen path segments out of the audit log.

A request that resolves to an upstream then enters the pipeline: an ordered slice of steps in `internal/router`, each returning either nothing or a refusal that ends the request. `newPipeline` is the order and `TestPipelineOrder` pins it.

- **Authentication** extracts the bearer token and verifies it against the upstream's canonical resource URI.
- **Authorization** runs the policy decision, audited on every allow and deny.
- **Session claim** refuses a repeated `Mcp-Session-Id` outright, and checks a single one against the binding table when the caller presented one and the transport does not manage its own sessions.
- **Body limit** buffers the body rather than wrapping it, so an overflow answers `413` instead of surfacing mid-stream.
- **Protocol checks** parse the revision from `MCP-Protocol-Version` and, for the header-mirroring era, validate the mirrored headers against the body.

Dispatch runs last, once every step above has returned nothing. The request is cloned with the identity injected into context, credentials stripped, and `URL.Path` reset to `/`, so the upstream never sees the `/mcp/<name>` prefix.

Two of those positions carry a security argument nothing else enforces, and `TestAuthenticationPrecedesEveryOtherCheck` holds them by driving every later step's refusal at an unauthenticated caller. Body limiting follows authentication, so a caller who never authenticates never has a body buffered on its behalf, and no authentication decision can turn on a body the caller chose. Protocol validation follows authentication, so an unauthenticated caller learns nothing about the upstream's protocol era from a mismatch refusal. Protocol validation also follows body limiting, because it reads the body that step buffered.

A refusal is a single value. It carries its status, its body, and the authorization decision to record, where one was reached. `Router.answer` is the only place one is written, so a decision a refusal carries can never be dropped before the response goes out. Its body format follows from its status: see [JSON-RPC Refusals](security.md#json-rpc-refusals).

## Token Verification

`auth.Tokens` holds every access and refresh token tailgate has issued, in memory, keyed by the SHA-256 digest of the token. `Verify` is a lookup. It rejects anything outside the [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) token grammar, an unknown or expired token, a token whose audience is not the requested upstream's canonical URI, and one missing a required scope. Access tokens live an hour and refresh tokens thirty days. Each table holds 16,384 entries and evicts the oldest when full, and a restart empties both.

The authorizer walks the upstream's rules in configured order and the first matching `allow` entry wins. Conditions within an entry are conjunctive.

## Authorization Server

tailgate issues the tokens its own resources accept. `internal/authserver` serves the OAuth endpoints at tailgate's origin, which is where the protected-resource metadata sends a spec-following client and where a client that assumes same-origin OAuth, claude.ai among them, looks first.

- `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` serve the same [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) document, since clients probe either name. It advertises `/authorize` and `/token`, the `code` response type, the authorization-code and refresh-token grants, no client authentication, S256 PKCE, resource indicators, and Client ID Metadata Document support.
- A client's `client_id` is an HTTPS URL. `internal/cimd` fetches the document there, through an egress-guarded client that refuses every non-global address and both tailnet ranges, follows no redirects, and caps the document at 16 KiB. The document must name the same `client_id`, list at least one redirect URI, and carry no secret. Documents cache for the lifetime their origin asks for, clamped between a minute and a day, and a failed fetch is never cached.
- `GET /authorize` answers only a connection from a tailnet peer, whose address the node resolves to a user with `WhoIs`. A Funnel connection carries no peer address, so a public browser gets a page saying to open the link from a tailnet device. The request must name a registered redirect URI, an S256 challenge, supported scopes, and a configured upstream's canonical URI as its `resource`. The consent page names the client, the host publishing its document, the redirect host, the upstream, and the person, and holds a pending entry for ten minutes.
- `POST /authorize` is the consent decision. It identifies the peer again, refuses a different person, and on approval mints a single-use code that lives five minutes and is bound to the client, redirect URI, challenge, scopes, resource, and identity.
- `POST /token` redeems a code against its PKCE verifier and issues an access and refresh pair, or rotates a refresh token. A replayed code revokes the pair it first issued. A refresh token presented by another client is consumed and refused. Any `client_secret` is refused, since no client has one.
- `/register` is absent. CIMD is the registration mechanism.

Every table is in memory and capped: pending authorizations, codes, redeemed codes, and tokens. Restarting tailgate forgets them all, and clients recover through the ordinary `401`.

## `proxy.Transport`

`proxy.Transport` is `http.Handler` plus `Shutdown` and `Close`. HTTP itself is the contract, carrying JSON bodies, SSE streams, session headers, and resumption without a bespoke message layer. A transport receives only authorized requests, already stripped and rewritten by the router, and owns its own timeout policy, since only it knows whether a response is a bounded JSON object or a stream that must stay open.

`internal/proxy` holds what both transports share. `StatusOf` maps the sentinel errors to statuses: unknown upstream and unknown session to `404`, which is the MCP signal to re-initialize, a caller at its child cap to `429`, an unreachable upstream to `502`, one that timed out to `504`, a draining transport to `503`, and anything unrecognized to `500`, since an unclassified failure must never pass as success. `Drain` is the shutdown sequence both transports embed: `Shutdown` stops accepting work and waits out in-flight requests, `Close` cancels whatever remains. `StripCredentials` implements the [credential strip](security.md#credential-stripping).

## HTTP Transport

`httptransport` wraps `httputil.ReverseProxy`. Construction never dials, so an unreachable upstream shows up per request as `502`. Compression is disabled and every write is flushed immediately, keeping SSE bytes intact and prompt. The rewrite pins the outbound path to exactly the configured target path, since URL joining would turn `/mcp` into `/mcp/` and exact-path upstreams reject that.

Each exchange gets a one-minute timeout, canceled the moment a response's `Content-Type` confirms `text/event-stream`.

## stdio Transport

`stdiotransport` implements the server side of streamable HTTP over a child process. Which lifecycle a caller gets depends on its era.

A caller's JSON-RPC ID never reaches the child. The transport substitutes a monotonic ID of its own on the way in and restores the caller's on the way out, whichever era the caller speaks. Independent POSTs from one caller may each call themselves request `1`, and a caller that hangs up mid-request and retries reuses an ID the child is still working on. Correlating on the caller's ID would let either request take the other's answer.

A notification is the one caller message that reaches the child unmodified, because it is the one carrying no ID at all. tailgate drops a child's server-initiated requests, so a client is never handed anything to answer. A POSTed response therefore answers nothing tailgate carried.

What such a response gets back differs by era. The stateful revisions make one legal, so it gets the `202` they specify. The stateless revision left no server-initiated request to answer, so there it is a `400`. Neither era forwards it to the child, since a caller-chosen ID in the minted namespace would let the child's answer satisfy the wrong request.

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

`main` loads the config and configures the tailnet node, then hands the node to `serve`, which runs a forced sequence: join the tailnet, seed resource URLs from the joined FQDN, build the token store and the authorization server over the node's `WhoIs`, assemble the router, then serve Funnel. Nothing serves until every step succeeds. `serve` takes the node as a `tsnetserver.Node`, so the sequence and the shutdown that reverses it run without a control server.

The join is bounded, because tsnet reprints a login URL forever for a node that cannot authenticate and an unbounded wait under launchd looks healthy while serving nothing. [deploying.md](deploying.md#startup-failures) covers the windows and the other startup checks.

## Reload

The router is the one piece a configuration change rebuilds. `SIGHUP` loads the file again, refuses a changed `node` section, runs the same assembly the startup did, and swaps the new router in atomically behind the listener. The previous router drains and closes in the background under the shutdown deadline. The token store, the authorization server, and the client metadata cache sit outside the router and reach the current one through the reloader for their upstream check, so a reload never invalidates a token and a resource added by a reload is authorizable as soon as the swap lands. A reload that fails at any step is logged and leaves the previous router serving. [deploying.md](deploying.md#reloading) covers what an operator sees.

Shutdown stops accepting connections, drains transports for up to 30 seconds so in-flight requests and open streams finish, gives remaining HTTP connections 10 more seconds, hard-closes what is left, then leaves the tailnet. The stdio transport's `Close` inverts the order and kills children first, since a request blocked on a child is released by that child's death.
