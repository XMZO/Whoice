# Operations

This is the production checklist for running Whoice after the core lookup flow is working.

## Health

- Public readiness: open `/status` in the Web UI.
- API probes: `GET /api/health`, `GET /api/version`, and `GET /api/capabilities`.
- Docker Compose uses service healthchecks so the Web container waits for the lookup API before serving traffic.
- Config reload errors are reported in API health/capabilities responses and on `/status`; the process keeps the last valid runtime config until the file is fixed.

## Metrics

Enable Prometheus text metrics in `data/whoice.toml`:

```toml
[metrics]
enabled = true
```

Scrape `/api/metrics` from a trusted network. The endpoint exposes lookup counters, provider counters, uptime, and lookup/provider latency histograms.

## Reporters

Async lookup reporters are configured under `[observability]`.

```toml
[observability]
reporter = "none" # none, log, webhook, or log,webhook
webhook_url = ""
timeout = "2s"
```

Webhook reporters should only target trusted internal endpoints. They run after lookup responses are produced and must not be treated as a lookup cache.

## Native Multi-Arch

Release images are built on native GitHub-hosted runners:

- `linux/amd64` on `ubuntu-latest`
- `linux/arm64` on `ubuntu-24.04-arm`

The container workflow publishes architecture-specific images first, then creates the multi-arch GHCR manifest. QEMU emulation is intentionally not used.

## Release

For a tagged release:

```sh
pnpm test
pnpm test:e2e --project=chromium --project=mobile-chrome
git tag v0.01
git push origin main
git push origin v0.01
```

The container workflow publishes:

- `ghcr.io/xmzo/whoice-lookup-api:<tag>`
- `ghcr.io/xmzo/whoice-web:<tag>`
- `latest` for non-manual tag builds

## Rollback

Use one of these rollback paths:

- Compose: pin both service images to the last known good tag and run `docker compose pull && docker compose up -d`.
- Runtime config: fix `data/whoice.toml`; hot reload will apply the next valid file automatically. The application rollback does not edit the file for you.
- Data snapshots: revert the data snapshot commit, then let CI re-run `pnpm test:data`.

## Data Updates

The scheduled data workflow refreshes RDAP bootstrap, registrar, PSL, brand, WHOIS server, and enrichment snapshots. It validates hashes and parser readability before committing changes.

Manual checks:

```sh
pnpm test:data
pnpm test:schema
```

## Browser Coverage

Playwright smoke tests cover desktop Chromium and mobile Chrome. The mobile project includes touch-target and no-horizontal-overflow checks so result layout changes stay usable on small screens.
