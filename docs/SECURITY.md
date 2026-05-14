# Security

Whoice treats lookup input and upstream responses as untrusted.

## Custom Servers

`allow_custom_servers = false` by default in `data/whoice.toml`. When custom RDAP or WHOIS servers are enabled, the API still rejects loopback, private, link-local, multicast, malformed, and unresolvable targets unless `allow_private_servers = true` is explicitly set for an admin-only environment.

## Authentication

Lookup requests can be protected without blocking health/version probes:

- `[auth] mode = "password"` with `site_password`.
- `[auth] mode = "token"` with `api_tokens`.

Accepted token carriers are `Authorization: Bearer ...`, `X-API-Key`, or the `token` query parameter. Password mode accepts `X-Whoice-Password`, `Authorization: Bearer ...`, or a `whoice_password` cookie.

## Rate Limit

Set `[rate_limit] enabled = true` and tune `anon`, for example `60/min`. The current adapter is an in-memory fixed-window limiter for single-node deployments; distributed limits are still planned.

## Webhook Reporter

The `[observability]` webhook reporter sends lookup summaries asynchronously after responses are returned. Only point `webhook_url` at trusted internal endpoints, because event payloads include queried names, provider timings, and error summaries.

## Admin Config

`/api/admin/config` is reserved for a future Web editor and is guarded by admin authentication. This build intentionally does not read or write the config source over HTTP; config changes should be made through the mounted `data/whoice.toml` file and the hot-reload validator.

## Raw Data

The web UI renders WHOIS/RDAP raw data as text, not HTML. Future linkification must keep this invariant and escape all upstream content.
