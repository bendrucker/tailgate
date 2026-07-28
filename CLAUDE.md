# tailgate build guide

tailgate is a single Go binary that fronts MCP servers behind Tailscale Funnel, validates tsidp OIDC tokens, and proxies authorized requests to HTTP or stdio MCP upstreams. `README.md` is the human overview. This file is the build contract for agents working in the repo.

## Locked decisions

- **Language.** Go, single binary, run under launchd.
- **Tailscale.** Embedded via `tsnet`. tailgate joins the tailnet as its own node and serves Funnel itself. No dependency on a host `tailscaled`.
- **Exposure.** Tailscale Funnel. Tailscale terminates TLS. Funnel supports TCP ports 443, 8443, and 10000 only.
- **Identity.** tsidp is the issuer. Validation runs in process with `go-oidc`. Funnel strips tailnet identity, so the bearer token is the only identity signal.
- **MCP auth.** tailgate is a spec-compliant OAuth Resource Server (MCP 2025-11-25, the current revision). It serves `/.well-known/oauth-protected-resource`, answers `401` with `WWW-Authenticate`, and validates token audience per RFC 8707. It never forwards the client's token to an upstream.
- **Routing.** Path prefix `/mcp/<name>`. Each upstream is a distinct protected resource with its own audience, which is its canonical URI.
- **Authorization.** Claim-match policy. `auth.Identity` carries `sub`, `email`, and the full claim set. Rules match on any claim. Config ships with email and sub allowlists.
- **Config.** HuJSON, a list of upstreams plus policy. Reload is process restart for now.
- **stdio upstreams.** One child process per MCP session, with a concurrency cap and idle reaping.
- **Audit.** Every allow and deny decision is logged with identity, upstream, and outcome via `log/slog`.

## Dependencies

- `tailscale.com` for the `tsnet` embedded node and Funnel listener.
- `github.com/coreos/go-oidc/v3` for OIDC discovery, JWKS, and token verification.
- `github.com/tailscale/hujson` for config parsing.
- `github.com/go-jose/go-jose/v4` for direct JOSE parsing of access tokens (see Must resolve first).
- `github.com/google/go-cmp` for test assertions.

Everything else is standard library: `net/http/httputil` for HTTP proxying, `os/exec` for stdio supervision, `log/slog` for audit.

## Build decomposition

Three layers plus a spike. A red-team pass found that two of the sketched contracts are wrong or unverified, so layer 1 is **provisional**, not frozen, and fan-out is blocked on the layer-1.5 spike below.

### Layer 1: spine (provisional)

- `internal/config` schema and loader. Implemented and stable.
- `internal/proxy` `Transport` and `Session` interfaces plus sentinel errors. **Provisional.** The seam is too thin for streamable HTTP: it opens and closes a session but never carries messages. The real seam must express a POST that returns either JSON or an SSE stream, a standalone GET server-to-client stream, HTTP DELETE termination, `Last-Event-ID` resumption, and the split where an HTTP upstream mints `Mcp-Session-Id` while a stdio upstream has none and tailgate synthesizes it over a JSON-RPC framing and correlation layer. The spike settles the final shape.
- `internal/auth` `Identity` and `Decision` types are stable. `NewVerifier` is **provisional**: it assumes the bearer is a JWT verifiable as an ID token, but MCP clients present an access token. The spike settles whether verification is go-jose JWT validation or RFC 7662 introspection.
- `internal/tsnetserver` node and Funnel constructors. Stable.
- **Add to the spine before fan-out:** a canonical `ResourceURL(name)` provider seeded after tsnet join (the tailnet FQDN is unknown until then, and the same string must match byte-for-byte across the client `resource` param, tsidp `aud`, the verifier, and each metadata doc), the shared error taxonomy, and the lifecycle and drain contract.

### Layer 1.5: spike (do before fan-out)

Fan-out is blocked until this resolves the provisional contracts:

- Stand up tsidp, run the flow with a `resource` param, and decode the resulting **access** token. Confirm its type, signature, and `aud`. Settles `NewVerifier`.
- Push one real MCP `initialize` plus a tool call end-to-end through a corrected `Transport` seam against a single HTTP upstream. Settles the seam shape.
- Pin the single canonicalization function for the resource URI.

Change the layer-1 interface signatures now, in the spike, not during fan-out.

### Layer 2: parallel units (fan out, no ordering between them)

Each builds against the layer-1 spine. Acceptance criteria in parentheses.

- `internal/tsnetserver` behavior: join, Funnel serve, graceful shutdown (node comes up, listener accepts).
- `internal/auth` verify path: validate tsidp tokens, reject the adversarial corpus (every hostile token denied, fail closed).
- `internal/auth` authorize path: evaluate policy against `Identity` (allow and deny match the rules).
- `internal/resource`: protected-resource metadata and `WWW-Authenticate` challenge (a real MCP client completes discovery).
- `internal/proxy/httptransport`: reverse-proxy streamable HTTP, preserve `Mcp-Session-Id` and the SSE stream.
- `internal/proxy/stdiotransport`: supervisor, per-session child, cap, idle reap (cap holds under load, children reaped when idle).
- `internal/audit`: structured decision log.

### Layer 3: integration and verification (after the layer-2 barrier)

- Wire everything in `main`.
- Conformance: adversarial token corpus, MCP client discovery, session fidelity, spawn-DoS cap.

## Must resolve first

- **Access-token shape.** `go-oidc`'s verifier is built for ID tokens. The bearer token an MCP client presents is an access token. Confirm against a pinned tsidp commit whether its access tokens are verifiable JWTs carrying `aud`. If not, verify with `go-jose` directly. This blocks the `auth` verify contract.
- **Pin tsidp.** Its claims and app-capability schema are pre-1.0. Pin a commit and re-verify the `groups` and `resource` behavior.
- **Target MCP 2025-11-25 (current).** Pin it explicitly so layer-2 agents do not diverge. The research that shaped this plan covered 2025-06-18, so re-verify the auth and discovery flow and the JSON-RPC batching rules against 2025-11-25, which is authoritative.
- **tsidp DCR is tailnet-only.** tsidp supports RFC 7591 dynamic client registration, but its registration endpoint is reachable only from within the tailnet. A public MCP client arriving over Funnel cannot self-register. Onboarding must register clients tailnet-side, or the client registers while on the tailnet. The protected-resource and authorization-server metadata tailgate surfaces should not promise self-registration to public clients.

## Provisioning (tailnet-side, outside the binary)

- Grant the `funnel` node attribute to tailgate's node.
- Configure the tsidp app-capability grant to authorize each upstream's resource URI and to populate any claims the policy matches on.

## Conventions

- No numbered phases or steps in code or names. Use descriptive functions called in sequence.
- Avoid catch-all packages. Keep each package well scoped.
- Fail closed. Any validation or authorization error denies the request.
- Log every authorization decision.

## Security invariants

tailgate is an internet-facing boundary where a validation gap is a remote exploit. Every request path holds these:

- **Fail closed.** Any verify, discovery, JWKS, or authorization error denies the request. A verifier-construction failure means the upstream is unavailable, never a passthrough.
- **No token passthrough.** Strip the client `Authorization` header before forwarding to any upstream. `httputil.ReverseProxy` forwards inbound headers by default. Strip inbound `X-Forwarded-*` and any identity header tailgate sets itself.
- **Exact-segment routing.** Decode and clean the path, then match the `/mcp/<name>` segment as exact membership in the configured upstream set. Reject `/mcp//x`, `/mcp/x/../y`, and `%2e%2e`. Route `/.well-known/oauth-protected-resource/mcp/<name>` to metadata rather than to the upstream.
- **Auth precedes spawn.** Token verify and the authz decision gate session creation. A stdio child is never spawned before authorization. The concurrency cap is per-identity-per-upstream, not global, so one caller cannot starve others.
- **Recover middleware.** A panic in the request path returns 500 and never proceeds to an upstream.
- **Origin validation.** Validate `Origin` against DNS rebinding, since tailgate is internet-facing via Funnel.
- **Timeouts.** Set `ReadHeaderTimeout` against Slowloris and `MaxBytesReader` on POST bodies. Exempt SSE streams from the request timeout, which is why timeout policy lives on the seam, not on a blanket `http.Server` setting.

## Curation

The build-decomposition and must-resolve sections are scaffolding for the initial build. Trim them once the code embodies the contracts and the open questions are resolved.
