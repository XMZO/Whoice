# Whoice

English | [简体中文](./README.zh-CN.md)

Whoice is a self-hosted WHOIS and RDAP lookup service for domains, IP addresses, CIDR ranges, and ASNs. It consists of a Go lookup API and a Next.js web interface.

- **Lookup**: RDAP and WHOIS queried in parallel and merged, with an optional WHOIS Web fallback, referral following, non-UTF-8 decoding, and TLD-specific parsers for more than 30 registries.
- **Enrichment**: multi-resolver DNS (UDP and DoH, compared per answer), EPP lock status, DNSSEC, ICANN registrar metadata, registrar and nameserver brands, DNSViz links, registration pricing, and Moz scores.
- **Optional modules**: ICP filing lookup, AI-assisted parsing of non-standard WHOIS records, password or token authentication, rate limiting, and Prometheus metrics.
- **Admin panel**: `/admin`, protected by a single password, edits every runtime setting and applies it immediately.
- **Web UI**: conclusion-first result page with a raw-response viewer, three languages (English, 简体中文, 繁體中文), light and dark themes, keyboard shortcuts, JSON export, results that stream in as each source answers, and a runtime `/status` page.
- **Freshness**: lookup results are never cached. Only slow-changing reference data (bootstrap files, server maps, ICP results, AI analysis) is reused.

## Deployment

Linux `amd64` and `arm64` images are published to GHCR. Create a directory and start the stack:

```sh
mkdir whoice && cd whoice
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/XMZO/Whoice/main/deploy/compose/docker-compose.yml
docker compose up -d
```

| Service | Address | Purpose |
|---|---|---|
| Web UI | `127.0.0.1:18081` | Browser interface; proxies API calls same-origin |
| Lookup API | `127.0.0.1:18080` | Direct API access |

Both ports are bound to localhost. Publish the web UI through a reverse proxy, for example Caddy:

```caddyfile
whois.example.com {
	reverse_proxy 127.0.0.1:18081
}
```

To expose the ports directly instead, change `127.0.0.1` to `0.0.0.0` in the `ports` entries of `docker-compose.yml`.

On first start the API creates `./data/whoice.toml`. All configuration and runtime data live in `./data`, next to the compose file.

**Updating**

```sh
docker compose pull && docker compose up -d
```

**IPv6.** The compose network `whoice` has IPv6 enabled, which requires IPv6 support in the Docker daemon (`"ipv6": true` in `daemon.json`). If the daemon has no IPv6, either enable it and recreate the network (`docker compose down && docker network rm whoice; docker compose up -d`), or disable direct IPv6 DNS probes with `ipv6_resolvers = []` under `[dns]`. DoH still returns AAAA records over IPv4.

## Admin Panel

Open `/admin` and sign in with the admin password. On first start the API generates one and prints it once:

```sh
docker compose logs lookup-api | grep "admin panel password"
```

The panel shows service status and edits every setting described below except the startup-only `server.addr` and `server.data_dir`. Saved changes are validated, written back to `data/whoice.toml` (the previous file is kept as `whoice.toml.bak`), and applied immediately. Change the password in the panel, set it with `WHOICE_ADMIN_PASSWORD`, or reset it:

```sh
docker compose exec lookup-api /app/whoice-api reset-admin-password
```

## Configuration

Settings can be changed in the admin panel or directly in `data/whoice.toml`. The generated file documents every option inline. Changes are hot-reloaded; only `server.addr` requires a restart. If an edit is invalid, the API keeps the last valid configuration and reports the error on `/status` and in lookup warnings. The file may also contain base64-encoded TOML.

| Section | Controls |
|---|---|
| `[server]` | Listen address, data directory, `trust_proxy`, custom and private lookup servers |
| `[api]` | Per-endpoint switches and an IP allowlist |
| `[auth]` | `none`, `password` (site password), or `token` (API tokens) |
| `[lookup]` | Timeouts, RDAP / WHOIS / WHOIS Web toggles, referral depth, DNS-first suffixes (registries with an unreachable WHOIS) |
| `[dns]` | Resolver pools (IPv4, IPv6, DoH), fake-IP filtering, DNSViz links |
| `[enrichment]` | EPP, registrar, brands, pricing (cached per suffix, 7 days by default; CNY/USD conversion with daily public exchange rates, cached 1 day), Moz |
| `[ai]` | OpenAI-compatible or Ollama endpoint, model, prompt, cache |
| `[icp]` | ICP filing lookup, caching, captcha handling, upstream service, extra ICP-fileable suffixes |
| `[rate_limit]` | Fixed-window limit for anonymous clients, e.g. `60/min` |
| `[metrics]`, `[observability]` | `/api/metrics` and lookup event reporters (log or webhook) |
| `[public_suffix]` | Optional Public Suffix List download at startup |

Many settings can also be supplied as environment variables (`WHOICE_AUTH_MODE`, `WHOICE_LOOKUP_TIMEOUT`, `WHOICE_ALLOW_CUSTOM_SERVERS`, …).

**Examples**

```toml
[auth]
mode = "token"
api_tokens = ["change-me"]

[rate_limit]
enabled = true
anon = "60/min"

[ai]
enabled = true
provider = "openai-compatible"          # or "ollama"
base_url = "https://api.example.com/v1"
api_key = "..."
model = "..."
```

**Notes**

- **Custom servers**: the `rdap_server`, `whois_server`, and `whois_follow` parameters are rejected unless `allow_custom_servers = true`. Private and loopback targets additionally require `allow_private_servers = true`. See [SECURITY.md](./docs/SECURITY.md).
- **AI parsing**: runs after the main result is returned, fills only fields the parsers left empty, and caches its analysis rather than lookup results. Set `cache_ttl = "0"` to disable the cache.
- **ICP**: served by a separate endpoint, so WHOIS and RDAP results are never delayed. Lookup is manual in the UI unless `auto_query = true`. Set `upstream_url` to use an ICP_Query-compatible service instead of querying MIIT directly.
- **DNS**: every configured resolver is sampled on each run to expose split-horizon differences. Set a resolver list to `none` to disable it.

## Data Overrides

Reference data is embedded in the images. Files placed under `./data` take precedence:

| Path | Replaces |
|---|---|
| `rdap-bootstrap/{dns,ipv4,ipv6,asn}.json`, `extra.json` | IANA RDAP bootstrap and the local overlay |
| `whois-servers/iana.json`, `extra.json` | WHOIS server maps |
| `public-suffix/public_suffix_list.dat`, `extra.dat` | Public Suffix List and local additions |
| `registrars/icann-accredited-registrars.csv` | ICANN registrar metadata |
| `brands/brand-map.json` | Registrar and nameserver brand rules |
| `pricing/pricing.json` | Local pricing fallback |
| `enrichment/moz.json` | Local Moz dataset |

When no RDAP server is known for a suffix, the API falls back to the live IANA bootstrap.

## API

| Endpoint | Description |
|---|---|
| `GET /api/lookup` | Lookup; returns `{ ok, result, error, meta }` |
| `POST /api/lookup/enrich` | Deferred enrichment (DNS, pricing) for a result |
| `POST /api/lookup/ai` | Background AI registration analysis |
| `GET /api/icp?domain=` | ICP filing lookup |
| `GET /api/health`, `/api/version`, `/api/capabilities` | Health, version and plugins, feature flags |
| `GET /api/metrics` | Prometheus metrics |
| `/api/admin/*` | Admin panel API (requires the admin password or session) |

Lookup parameters: `query` (domain, IP, CIDR, ASN, or URL), `rdap=1` or `whois=1` to use a single source, `exact_domain=1` to skip registrable-domain reduction, `stream=1` for NDJSON previews as each source answers (the web UI uses this), and `rdap_server`, `whois_server`, `whois_follow` for custom servers.

```sh
curl "http://127.0.0.1:18080/api/lookup?query=example.com"
```

The response schema is defined in [`packages/schema`](./packages/schema). The web UI includes an API reference at `/docs`.

## Development

Requirements: Go 1.26, Node.js 24, pnpm 10.

```sh
pnpm install
pnpm dev:api    # API on :8080; creates ./data/whoice.toml
pnpm dev:web    # Web UI on :18081
```

| Command | Checks |
|---|---|
| `pnpm test` | All checks below except end-to-end tests |
| `pnpm test:api` | Go unit tests |
| `pnpm test:web` | TypeScript, the theme contract guard, and the i18n gate |
| `pnpm test:schema` | JSON Schema, OpenAPI, and fixture contracts |
| `pnpm test:data` | Data snapshot manifests, hashes, and routing |
| `pnpm test:pre5`, `pnpm test:phase5` | Architecture and productionization guardrails |
| `pnpm test:e2e` | Playwright on desktop and mobile Chrome |

The i18n gate (`pnpm test:i18n`) fails when user-visible text in the web app bypasses translation. Use `t("key")` for shared strings in `lib/i18n.tsx` (all three locales must define every key) and `t3("English", "简体中文", "繁體中文")` for page-specific text.

Live WHOIS checks are skipped by default; run them with `WHOICE_LIVE_WHOIS_SMOKE=1 go test ./services/lookup-api/internal/providers/whois -run TestLiveWHOISSmoke`. After an intentional API shape change, regenerate the runtime fixtures with `WHOICE_UPDATE_RUNTIME_FIXTURES=1`. Refresh the Public Suffix List with `pnpm update:psl`.

To build images locally:

```sh
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.build.yml up --build
```

## Releases

Pushing a version tag (for example `v0.1.0`) publishes `ghcr.io/xmzo/whoice-lookup-api` and `ghcr.io/xmzo/whoice-web`. Each architecture is built on native GitHub-hosted runners and combined into a multi-arch manifest; the workflow does not use QEMU emulation.

## Documentation

- [docs/OPERATIONS.md](./docs/OPERATIONS.md): health checks, metrics, reporters, releases, rollback, and data updates
- [docs/SECURITY.md](./docs/SECURITY.md): custom servers, authentication, rate limiting, and webhook reporters
- [docs/IMPLEMENTATION_STATUS.md](./docs/IMPLEMENTATION_STATUS.md): implemented features versus the plan
- [docs/COMPATIBILITY_BACKLOG.md](./docs/COMPATIBILITY_BACKLOG.md): parser and WHOIS Web coverage backlog
- [PLAN.md](./PLAN.md): architecture and roadmap
