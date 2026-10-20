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

The admin panel (`/admin`) and every `/api/admin/*` endpoint use a single admin password that is independent of visitor authentication.

- On first start the API generates a random password, stores a PBKDF2-SHA256 hash in `data/admin.json` (mode 0600), and prints the password once in the log. `WHOICE_ADMIN_PASSWORD` overrides the stored password; it can then only be changed in the environment.
- Signing in sets an HttpOnly, `SameSite=Strict` session cookie, marked `Secure` when the request arrives over HTTPS (`X-Forwarded-Proto`). Sessions last 7 days and are revoked by a password change or reset. Scripts may send the password in `X-Whoice-Admin-Password` instead.
- State-changing requests require the `X-Whoice-Admin: 1` header, which cross-site forms cannot set.
- Failed sign-ins are limited to 5 per client and 50 in total per 15 minutes.
- Saving settings validates the merged configuration with the same rules as hot reload, rewrites `data/whoice.toml` atomically, and keeps the previous file as `whoice.toml.bak`. Secrets (site password, API tokens, AI key, webhook URL) are never returned to the browser. The panel rejects changes that would lock it out (disabling the API or admin endpoints, or an IP allowlist that excludes the current client), startup-only keys (`server.addr`, `server.data_dir`), and keys overridden by environment variables.
- Reset a forgotten password with `docker compose exec lookup-api /app/whoice-api reset-admin-password`. Disable the panel entirely with `admin = false` under `[api.endpoints]`.

## Raw Data

The web UI renders WHOIS/RDAP raw data as text, not HTML. Future linkification must keep this invariant and escape all upstream content.
