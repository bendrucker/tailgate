# Deploying tailgate

## Installing

```
go install github.com/bendrucker/tailgate@latest
```

## Tailnet setup

tsidp must already be running on the tailnet. [Tailscale's tsidp documentation](https://tailscale.com/docs/features/tsidp) covers deploying it. Its URL is the `oidc.issuer` value.

Grant the `funnel` node attribute to tailgate's node. Without it, Funnel fails at the public edge.

Generate the tsidp grant and append it to the policy:

```
tailgate grant -config /etc/tailgate.hujson >> tailnet-policy/grants.hujson
```

This needs `node.tailnet` in the config, since the resource URIs are built from the node's FQDN. Add `-allow-admin-ui` if you will register clients through tsidp's admin UI, and `-allow-dcr` for dynamic client registration. Neither is granted by default.

Register each MCP client with tsidp as a confidential client, from a tailnet device, in tsidp's admin UI at the issuer origin. `/register` and the admin UI are reachable only from the tailnet, and tailgate does not front `/register`.

Authorizing a client sends a browser to tsidp's `/authorize`, which tsidp refuses over Funnel. Whoever completes that step must be on the tailnet.

Give the client its `client_id` and `client_secret`, plus the RFC 8707 `resource` value for the upstream it calls. That value is the canonical URI `tailgate grant` emits, `https://<node>.<tailnet>.ts.net/mcp/<name>`. A client that omits `resource` on the token request gets a token carrying no resource audience, and every one of its requests then fails the audience check.

A client that discovers its authorization server from the RFC 9728 metadata needs no further configuration. One that asks for an authorization server URL outright takes tailgate's own origin, `https://<node>.<tailnet>.ts.net`, which fronts `/authorize` and `/token`.

Clients must request the `email` scope. Introspection omits `email` without it, and an email allowlist then denies every request from that client.

## Running as a service

Set `TS_AUTHKEY` for the first start so the node joins unattended. A launchd sketch:

```xml
<dict>
  <key>Label</key><string>com.bendrucker.tailgate</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/tailgate</string>
    <string>-config</string>
    <string>/etc/tailgate.hujson</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>TS_AUTHKEY</key><string>tskey-auth-...</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ExitTimeOut</key><integer>60</integer>
</dict>
```

The systemd equivalent:

```ini
[Service]
ExecStart=/usr/local/bin/tailgate -config /etc/tailgate.hujson
Environment=TS_AUTHKEY=tskey-auth-...
Restart=always
TimeoutStopSec=60
```

`SIGINT` and `SIGTERM` drain in-flight requests and open SSE streams for up to 30 seconds, then wait up to 10 more for the connections that remain. The supervisor's kill timeout must exceed the 40-second total.

## Node keys

Node keys expire on the tailnet's key expiry schedule, six months by default. Disable expiry for tailgate's node, or use an auth key scoped to a tag. An expired key takes tailgate offline until someone reauthorizes it by hand.

## Startup failures

A node with no auth key and no saved state exits after 90 seconds rather than waiting on a login nobody is there to complete. Run once with `-open-login` on a machine with a browser to authorize interactively, which waits five minutes.

An optional top-level `favicon` names an icon served at `/favicon.ico`, alongside a root page linking it. Crawlers index it for the origin, which is where a client like claude.ai gets a connector's icon. Without it a `*.ts.net` node shows Tailscale's logo. A configured icon that cannot be read, or that is zero bytes, fails startup.

The issuer's discovery document must carry an `issuer` field equal to the configured `oidc.issuer`. It must advertise an `introspection_endpoint`, and that endpoint must share the issuer's scheme and host. Any of these failing stops tailgate before it serves.

Setting `node.tailnet` also makes tailgate check the name the join reports. A mismatch stops it from serving.

## Policy evaluation

Policy is allow-only. An upstream with no policy rule is reachable by nobody.

Every condition within one `allow` entry must match.

A `sub` value is the bare decimal user ID, not the `userid:N` form that appears in ID tokens.

Besides `sub` and `email`, a `claim` map matches the other claims introspection returns, which are `username` and `scope`. Grant `extraClaims`, including `groups`, appear only in ID tokens and userinfo, so no policy can match on them.

## Fixed limits

Request bodies are capped at 1 MiB. Sessions expire after an hour. A verified token is cached for up to five minutes, and never past its own expiry. The config file has no keys for any of these.

On a stdio upstream, `max_children` and `idle_timeout` are the only tunable limits.

## Operating notes

The Funnel listener also accepts tailnet peers dialing the same port. Those requests still need a bearer token, because Funnel strips tailnet identity.

Setting `TAILGATE_TSNET_DEBUG` to any non-empty value routes the embedded node's internal logs to `slog`. Funnel ingress problems show up there.
