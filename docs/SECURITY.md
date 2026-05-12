# Security

Whoice treats lookup input and upstream responses as untrusted.

## Custom Servers

`WHOICE_ALLOW_CUSTOM_SERVERS=false` by default. When custom RDAP or WHOIS servers are enabled, the API still rejects loopback, private, link-local, multicast, malformed, and unresolvable targets unless `WHOICE_ALLOW_PRIVATE_SERVERS=true` is explicitly set for an admin-only environment.

## Authentication

Lookup requests can be protected without blocking health/version probes:

- `WHOICE_AUTH_MODE=password` with `WHOICE_SITE_PASSWORD`.
- `WHOICE_AUTH_MODE=token` with comma-separated `WHOICE_API_TOKENS`.

Accepted token carriers are `Authorization: Bearer ...`, `X-API-Key`, or the `token` query parameter. Password mode accepts `X-Whoice-Password`, `Authorization: Bearer ...`, or a `whoice_password` cookie.

## Rate Limit

Set `WHOICE_RATE_LIMIT_ENABLED=true` and tune `WHOICE_RATE_LIMIT_ANON`, for example `60/min`. The current adapter is an in-memory fixed-window limiter for single-node deployments; distributed limits are still planned.

## Raw Data

The web UI renders WHOIS/RDAP raw data as text, not HTML. Future linkification must keep this invariant and escape all upstream content.
