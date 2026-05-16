# Whoice

Whoice is a modular WHOIS/RDAP lookup platform. It combines a Go lookup API with a Next.js web UI, while keeping optional capabilities such as auth, enrichment, and custom data sources pluggable.

See [PLAN.md](./PLAN.md) for the detailed architecture and implementation roadmap.
See [docs/IMPLEMENTATION_STATUS.md](./docs/IMPLEMENTATION_STATUS.md) for the current plan-vs-code audit.

## Development

```sh
pnpm install
pnpm dev:api
```

In another terminal:

```sh
pnpm dev:web
```

For local development, the web app defaults to `http://localhost:18081`; the lookup API defaults to `http://localhost:8080`. Browser lookups go through the web app's same-origin `/api/lookup` proxy, so result-page searches update in place instead of doing a full page reload. Open `http://localhost:18081/status` to inspect API health, version, enabled capabilities, and plugin descriptors through the same-origin proxy. `pnpm dev:api` creates `./data/whoice.toml` on first run; edit it to test AI, ICP, DNS, auth, or enrichment settings.

## Testing

```sh
pnpm test                         # Go API + Web typecheck + schema/contracts
pnpm test:api                     # Go tests only
pnpm test:web                     # Next.js/TypeScript typecheck + theme contract guard
pnpm test:schema                  # JSON Schema/OpenAPI/fixture contract checks
pnpm test:data                    # Snapshot manifest/sync/routing checks
pnpm test:pre5                    # PLAN Phase 0-4 guardrails
pnpm test:phase5                  # Productionization guardrails
pnpm test:e2e --project=chromium  # Playwright smoke tests
pnpm test:e2e --project=mobile-chrome # Mobile/touch smoke tests
pnpm build                        # Production web build
```

`test:schema` validates curated samples, parser fixtures, and deterministic runtime API fixtures for RDAP domain, WHOIS domain, WHOIS Web fallback, RDAP IPv4, and invalid-query responses. When a reviewed API response shape intentionally changes, regenerate the runtime fixtures with `WHOICE_UPDATE_RUNTIME_FIXTURES=1 go test ./services/lookup-api/internal/httpapi -run TestRuntimeLookupResponsesMatchSchemaFixtures`.
`test:data` validates RDAP bootstrap, ICANN registrar, PSL, brand, enrichment, and WHOIS server snapshots; it also checks manifest hashes, embedded snapshot sync, and critical second-level suffix routing such as `pp.ua`, `eu.org`, `qzz.io`, `edu.kg`, `de5.net`, `cc.cd`, and `us.ci`.
Optional live TCP WHOIS smoke checks are disabled by default to keep CI deterministic. Run `WHOICE_LIVE_WHOIS_SMOKE=1 go test ./services/lookup-api/internal/providers/whois -run TestLiveWHOISSmoke -count=1` when you want to validate current upstream WHOIS behavior.
`test:web` also runs a lightweight theme guard. It checks that `theme.css` stays token-only, that every theme variable used by the UI is defined by the base theme contract, and that critical lookup controls/results are not statically hidden by theme CSS.
`test:phase5` checks the productionization surface: health/status/metrics, async reporters, data update workflow, runtime API fixtures, native multi-arch release workflow, Docker healthchecks, desktop/mobile Playwright coverage, and security/operations docs.

## Docker

Use the published linux multi-arch images on a Debian VPS by downloading the compose file directly:

```sh
mkdir -p whoice
cd whoice
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/XMZO/Whoice/main/deploy/compose/docker-compose.yml
docker compose up -d
```

`docker-compose.yml` is designed to work as a single downloaded file. First startup creates `./data/whoice.toml` with comments; edit that file while the API is running and most runtime changes hot-reload automatically. If a change is invalid, Whoice keeps using the last valid runtime config, logs the error, and shows the rollback state on `/status` and lookup warnings. Runtime data lives in the same folder under `./data`, mounted into the API container as `/data`. Docker exposes the Web UI on `0.0.0.0:18081` and the direct API on `0.0.0.0:18080`; edit the two `ports` lines in `docker-compose.yml` if you need different host ports.

The compose file uses the published `latest` multi-arch images directly, so no `.env` file or local image build is required.
If the GHCR packages are private, run `docker login ghcr.io` on the VPS first.

For local image development:

```sh
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.build.yml up --build
```

The compose stack uses an explicit `whoice` bridge network and container healthchecks. The web container calls the API over the internal network, and the browser uses the web app's same-origin API proxy for in-place searches and status inspection. The generated config enables `trust_proxy = true` so optional rate limits can use the forwarded client IP. Lookup results are not cached, so WHOIS/RDAP responses stay live; only slow-changing, validated data snapshots such as RDAP bootstrap, PSL, WHOIS server maps, ICANN registrar metadata, ICP results, and optional AI analysis are reused.

Docker containers do not automatically inherit host IPv6 routing. Docker daemon `"ipv6": true` and `fixed-cidr-v6` prepare Docker IPv6 support, and the compose file enables IPv6 on the `whoice` custom bridge without pinning a custom IPv6 subnet, letting Docker Engine auto-allocate one. If an older `whoice` network already exists from before IPv6 was enabled, recreate it first. DoH can still query both A and AAAA records over IPv4 HTTPS; disabling IPv6 UDP sampling only removes the direct IPv6 UDP resolver probes.

After Docker daemon IPv6 is enabled and Docker is restarted, recreate the compose network:

```sh
docker compose down
docker network rm whoice || true
docker compose up -d
```

Optional mounted data layout:

```text
whoice/
  docker-compose.yml
  data/
    rdap-bootstrap/
      dns.json
      ipv4.json
      ipv6.json
      asn.json
      extra.json
    registrars/
      icann-accredited-registrars.csv
    brands/
      brand-map.json
    pricing/
      pricing.json
    enrichment/
      moz.json
    whois-servers/
      iana.json
      extra.json
    public-suffix/
      public_suffix_list.dat
      extra.dat
```

If `data/rdap-bootstrap` is empty, Whoice uses embedded RDAP bootstrap snapshots, a small `extra.json` RDAP overlay, and then live IANA fallback. The overlay covers ccTLDs and second-level suffixes that have working RDAP but are missing from IANA bootstrap data, including `.li`, `.ch`, and CentralNic-style domains such as `eu.com`.
If `data/registrars/icann-accredited-registrars.csv` is present, it overrides the embedded ICANN registrar snapshot used to fill missing registrar URL, IANA ID, and country fields.
If `data/brands/brand-map.json` is present, it overrides the embedded registrar/nameserver brand rules. This keeps the brand UI inspired by `unofficial/next-whois` as data, not hard-coded page logic.
If `data/pricing/pricing.json` is present, it provides the optional local Pricing fallback dataset. `data/enrichment/pricing.json` is still accepted as a legacy runtime path, but new installs should use `data/pricing/pricing.json` so pricing can evolve independently from other enrichment data. When `pricing = true`, the pricing module also maintains a Miqingju public price snapshot in memory and refreshes it periodically; lookup responses show the lowest registration and renewal registrar independently when the source provides that detail. If `data/enrichment/moz.json` is present, it overrides the optional local Moz dataset. Enable those enrichers in `data/whoice.toml` with `pricing = true` or `moz = true`.
If `data/whois-servers/iana.json` or `data/whois-servers/extra.json` is present, it overrides the embedded WHOIS server maps. This is useful for ccTLDs and CentralNic-style second-level domains without rebuilding images.
If `data/public-suffix/public_suffix_list.dat` is present, it overrides the embedded Public Suffix List snapshot. `data/public-suffix/extra.dat` is then applied as a small local overlay for emergency additions. Set `auto_update = true` under `[public_suffix]` in `data/whoice.toml` to fetch the official PSL into `./data` once during API startup; the default is off so compose deployments can start without depending on publicsuffix.org.

Manual PSL refresh for maintainers:

```sh
pnpm update:psl
```

All reviewable data snapshots under `packages/data` are checked by `pnpm test:data`. Scheduled data updates also run that validator before committing refreshed snapshots.

## Release Images

Pushing a version tag builds and publishes `linux/amd64` and `linux/arm64` images to GHCR. The workflow uses native GitHub-hosted runners for both architectures and then publishes a multi-arch manifest; it does not use QEMU emulation.

```sh
git add .
git commit -m "Release v0.01"
git tag v0.01
git push origin main
git push origin v0.01
```

Images:

- `ghcr.io/xmzo/whoice-lookup-api`
- `ghcr.io/xmzo/whoice-web`

## Current MVP

- Go lookup API: `/api/lookup`, `/api/health`, `/api/version`, `/api/capabilities`, `/api/metrics`
- Query normalization for domains, URLs, IPv4, IPv6, ASN, and CIDR
- RDAP provider through IANA bootstrap, mounted/embedded overlay data, and explicit custom server override
- Embedded, reviewable RDAP bootstrap snapshots for DNS, IPv4, IPv6, and ASN routing with manifest hash validation
- WHOIS provider with embedded and mounted TLD server data, query templates, referral follow, and non-UTF-8 response decoding
- DNS enrichment for domain results
- Optional ICP filing lookup for domains through the MIIT endpoint, isolated from the main lookup path and cached under `./data/cache`
- Generic RDAP/WHOIS parsers plus initial UK/JP/FR/CN/BR/IT/EU/BE/PL/CZ/HU/SK/RO/DE/NL/CA/AU/SE+NU/FI/KR/AT/RU+SU/EE/BG/KG/TR/HK/TW/SI/UA/ID TLD parsers, fixtures, and a simple merger
- Optional WHOIS Web fallback provider with isolated modules, including selected manual notice fallbacks and `.dz`/`.ni`/`.vn` API fallbacks
- Optional password/token auth and fixed-window rate limit for lookup requests
- EPP status enrichment, ICANN registrar metadata enrichment, DNSViz links, and optional registrar/nameserver brand enrichment through an embedded or mounted brand map
- Conservative custom server SSRF policy
- Admin status endpoint, public Web `/status` runtime inspector, trace IDs, and structured request logs
- Prometheus-style metrics endpoint for lookup/provider counters and latency histograms
- Provider trace output for debugging and admin observability
- OpenAPI/JSON Schema contract checks with generated TypeScript types, parser fixture samples, runtime API fixture samples, data snapshot validation, and Go/Web drift guards
- Next.js search UI, All/RDAP/WHOIS source modes, shared local history, result panels, local plugin renderers, raw evidence display, runtime status page, API docs, theme, i18n, PWA, Dynamic OG, keyboard shortcuts, share/export menu, copy URL/query/raw, download JSON, and download OG image actions
- Playwright smoke coverage for hydration, runtime status, result-page in-place lookup, source switching, theme/language controls, null-array response tolerance, and DNSViz rendering

## Runtime Controls

Edit `data/whoice.toml`; the API hot-reloads it automatically:
Only startup-only settings such as `server.addr` still need an API process/container restart.
For compact or playful deployments, the same file can contain a base64-encoded TOML document; startup and hot reload decode it automatically before applying validation.

Password auth:

```toml
[auth]
mode = "password"
site_password = "change-me"
```

Bearer/API token auth:

```toml
[auth]
mode = "token"
api_tokens = ["token-one", "token-two"]
```

Rate limit:

```toml
[rate_limit]
enabled = true
anon = "60/min"
```

Metrics:

```toml
[metrics]
enabled = true
```

Observability reporters:

```toml
[observability]
# none, log, webhook, or log,webhook
reporter = "none"
webhook_url = ""
timeout = "2s"
```

Reporter events are asynchronous lookup summaries. They never cache lookup results and do not replace `/api/metrics`; use `webhook` only for trusted internal endpoints.

DNS enrichment:

```toml
[dns]
enabled = true
timeout = "3s"
ipv4_resolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "180.184.1.1", "180.184.2.2"]
ipv6_resolvers = ["2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"]
doh_resolvers = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
  "https://doh.pub/dns-query",
  "https://dns.alidns.com/dns-query",
]
filter_fake_ip = true
dnsviz_enabled = true
```

The default DNS resolver pool samples Cloudflare IPv4/IPv6, Google IPv4/IPv6, ByteDance/Volcengine IPv4 public DNS, and configured DoH endpoints on every DNS enrichment run. This exposes geo/ISP split DNS differences instead of stopping at the first successful resolver. DoH uses Cloudflare, Google, Tencent `doh.pub`, and AliDNS; each A/AAAA answer records which resolver saw it. Set any resolver list to `none` to disable it, or replace the comma-separated list with your own resolvers. Fake-IP answers in `198.18.0.0/15` are hidden only when a non-reserved replacement exists; otherwise they are kept with a warning.

For Docker hosts where container IPv6 is not enabled, this is the recommended DNS override:

```toml
[dns]
ipv6_resolvers = []
doh_resolvers = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
  "https://doh.pub/dns-query",
  "https://dns.alidns.com/dns-query",
]
```

AI-assisted registration parsing:

```toml
[ai]
enabled = false
provider = "openai-compatible"
base_url = ""
api_key = ""
model = ""
timeout = "8s"
cache_ttl = "168h"
max_input_chars = 16000
min_confidence = 0.68
temperature = 0
max_output_tokens = 700
prompt = ""
```

AI parsing is optional and disabled by default. The main `/api/lookup` result does not wait for AI; the Web UI calls `POST /api/lookup/ai` in the background when `ai=1` is enabled, shows an analyzing badge, then merges any AI-filled fields into the registration panel. AI only fills missing registrar or public registrant fields; existing parsed fields are not overwritten. The built-in English prompt asks for concise strict JSON only, explicitly avoiding markdown, commentary, reasoning, and `<think>` blocks. It also asks the model to decode escaped Unicode values such as `\u0130zmir` into readable text while keeping evidence snippets verbatim. `temperature` defaults to `0`, `max_output_tokens` defaults to `700`, and `prompt` can replace the prompt. The UI marks AI-derived fields with a compact confidence badge.

Cloudflare Workers AI can be used through its OpenAI-compatible endpoint:

```toml
[ai]
enabled = true
base_url = "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/v1"
api_key = "<CF_API_TOKEN>"
model = "@cf/meta/llama-3.1-8b-instruct"
```

For local parsing with Ollama:

```toml
[ai]
enabled = true
provider = "ollama"
base_url = "http://host.docker.internal:11434"
model = "qwen2.5:1.5b-instruct"
```

`qwen2.5:0.5b-instruct` is lighter but less reliable; `qwen2.5:1.5b-instruct` is the practical small default. AI cache stores only the model's structured analysis keyed by raw evidence, model, and prompt. It does not cache WHOIS/RDAP/DNS lookup results, so live lookup freshness is preserved. Set `cache_ttl = "0"` or `"none"` for no AI cache, or `"forever"` for permanent AI analysis cache.

ICP filing lookup:

```toml
[icp]
enabled = true
auto_query = false
timeout = "8s"
cache_ttl = "72h"
negative_cache_ttl = "12h"
error_cache_ttl = "10m"
captcha_enabled = true
captcha_retries = 3
upstream_url = ""
blocklist = []
```

`/api/icp?domain=example.cn` is separate from `/api/lookup`, so WHOIS/RDAP/DNS results render first. The Web UI defaults to a manual ICP button; set `auto_query = true` to make the panel request it automatically after the main result loads. Positive results are cached longer than empty/error responses to reduce MIIT endpoint pressure while keeping freshness reasonable.

Whoice includes a direct MIIT mode with token plus slider-captcha support. If MIIT changes its protection or your network is frequently challenged, set `upstream_url` to an ICP_Query-compatible service, for example `http://127.0.0.1:16181`; Whoice will call `/query/web?search=domain` and still keep its own cache, blacklist hiding, and UI behavior. Cache TTL values accept Go durations such as `72h`, `0`/`none`/`off` for no cache, or `forever`/`permanent` for never-expiring entries. The default file cache is the best fit for single-file VPS deployment; SQLite is a good later step if query history and richer local indexing become necessary, while Redis is mainly for multi-instance deployments. `blocklist` accepts domains or `*.example.com` patterns; blocked names return the same empty-looking result as a normal miss.

WHOIS Web fallback:

```toml
[lookup]
whois_web_enabled = true
```

EPP, registrar, and brand enrichment:

```toml
[enrichment]
epp = true
registrar = true
brands = true
# Price lookup is only an on/off switch here. The pricing module owns its data source
# and currently uses a Miqingju public snapshot with local JSON fallback.
pricing = false
moz = false
```

Brand map override:

```sh
mkdir -p data/brands
# edit data/brands/brand-map.json next to docker-compose.yml
```

Custom lookup servers are exposed through the Advanced panel in the Web UI and through the API parameters `rdap_server`, `whois_server`, and `whois_follow`. They remain blocked unless `allow_custom_servers = true` is set under `[server]`; private/loopback custom targets stay blocked unless `allow_private_servers = true` is also set for an admin-only environment.
