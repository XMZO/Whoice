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

For local development, the web app defaults to `http://localhost:18081`; the lookup API defaults to `http://localhost:8080`. Browser lookups go through the web app's same-origin `/api/lookup` proxy, so result-page searches update in place instead of doing a full page reload. Open `http://localhost:18081/status` to inspect API health, version, enabled capabilities, and plugin descriptors through the same-origin proxy. Set `WHOICE_WEB_PORT` when you want a different local Web port.

## Testing

```sh
pnpm test                         # Go API + Web typecheck + schema/contracts
pnpm test:api                     # Go tests only
pnpm test:web                     # Next.js/TypeScript typecheck only
pnpm test:schema                  # JSON Schema/OpenAPI/fixture contract checks
pnpm test:e2e --project=chromium  # Playwright smoke tests
pnpm build                        # Production web build
```

## Docker

Use the published linux multi-arch images on a Debian VPS by downloading the compose file directly:

```sh
mkdir -p whoice/data
cd whoice
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/XMZO/Whoice/main/deploy/compose/docker-compose.yml
docker compose pull
docker compose up -d
```

`docker-compose.yml` is designed to work as a single downloaded file. Runtime data lives in the same folder under `./data`, mounted into the API container as `/data`. By default Docker exposes the Web UI on `0.0.0.0:18081` and the direct API on `0.0.0.0:18080`; override them with `WHOICE_WEB_BIND` and `WHOICE_API_BIND` when needed. The Web container listens on `8081` internally, and the API container listens on `8080` internally.

The compose file defaults to `latest`, so you do not need to set `WHOICE_IMAGE_TAG`. Set `WHOICE_IMAGE_TAG=0.01alpha` only when you want to pin or roll back to that exact release.
If the GHCR packages are private, run `docker login ghcr.io` on the VPS first.

For local image development:

```sh
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.build.yml up --build
```

The compose stack uses an explicit `whoice` bridge network and container healthchecks. The web container calls the API over the internal network, and the browser uses the web app's same-origin API proxy for in-place searches and status inspection. Compose enables `WHOICE_TRUST_PROXY=true` so optional rate limits can use the forwarded client IP. Lookup results are not cached, so WHOIS/RDAP responses stay live; only slow-changing data snapshots such as RDAP bootstrap and ICANN registrar metadata are reused.

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
    registrars/
      icann-accredited-registrars.csv
    brands/
      brand-map.json
    enrichment/
      pricing.json
      moz.json
    whois-servers/
      iana.json
      extra.json
    public-suffix/
      public_suffix_list.dat
      extra.dat
```

If `data/rdap-bootstrap` is empty, Whoice uses embedded RDAP bootstrap snapshots and then live IANA fallback. Put updated files there when you want to override data without rebuilding images.
If `data/registrars/icann-accredited-registrars.csv` is present, it overrides the embedded ICANN registrar snapshot used to fill missing registrar URL, IANA ID, and country fields.
If `data/brands/brand-map.json` is present, it overrides the embedded registrar/nameserver brand rules. This keeps the brand UI inspired by `unofficial/next-whois` as data, not hard-coded page logic.
If `data/enrichment/pricing.json` or `data/enrichment/moz.json` is present, it overrides the optional local Pricing/Moz datasets. These enrichers stay disabled unless `WHOICE_ENRICH_PRICING=true` or `WHOICE_ENRICH_MOZ=true`.
If `data/whois-servers/iana.json` or `data/whois-servers/extra.json` is present, it overrides the embedded WHOIS server maps. This is useful for ccTLDs and CentralNic-style second-level domains without rebuilding images.
If `data/public-suffix/public_suffix_list.dat` is present, it overrides the embedded Public Suffix List snapshot. `data/public-suffix/extra.dat` is then applied as a small local overlay for emergency additions. Set `WHOICE_PSL_AUTO_UPDATE=true` to fetch the official PSL into `./data` once during API startup; the default is off so compose deployments can start without depending on publicsuffix.org.

Manual PSL refresh for maintainers:

```sh
pnpm update:psl
```

## Release Images

Pushing a version tag builds and publishes `linux/amd64` and `linux/arm64` images to GHCR. The workflow uses native GitHub-hosted runners for both architectures and then publishes a multi-arch manifest; it does not use QEMU emulation.

```sh
git add .
git commit -m "Release 0.01alpha"
git tag 0.01alpha
git push origin main
git push origin 0.01alpha
```

Images:

- `ghcr.io/xmzo/whoice-lookup-api`
- `ghcr.io/xmzo/whoice-web`

## Current MVP

- Go lookup API: `/api/lookup`, `/api/health`, `/api/version`, `/api/capabilities`, `/api/metrics`
- Query normalization for domains, URLs, IPv4, IPv6, ASN, and CIDR
- RDAP provider through IANA bootstrap with `rdap.org` fallback
- Embedded RDAP bootstrap snapshot fallback for common TLDs, RIR IP ranges, and ASNs
- WHOIS provider with embedded and mounted TLD server data, query templates, referral follow, and non-UTF-8 response decoding
- DNS enrichment for domain results
- Generic RDAP/WHOIS parsers plus initial UK/JP/FR/CN/BR/IT/EU/BE/PL/CZ/HU/SK/RO TLD parsers, fixtures, and a simple merger
- Optional WHOIS Web fallback provider with isolated modules, including selected manual notice fallbacks and `.vn` API fallback
- Optional password/token auth and fixed-window rate limit for lookup requests
- EPP status enrichment, ICANN registrar metadata enrichment, DNSViz links, and optional registrar/nameserver brand enrichment through an embedded or mounted brand map
- Conservative custom server SSRF policy
- Admin status endpoint, public Web `/status` runtime inspector, trace IDs, and structured request logs
- Prometheus-style metrics endpoint for lookup/provider counters and latency histograms
- Provider trace output for debugging and admin observability
- OpenAPI/JSON Schema contract checks with generated TypeScript types and Go/Web drift guards
- Next.js search UI, All/RDAP/WHOIS source modes, local history, result panels, local plugin renderers, raw evidence display, runtime status page, theme, i18n, PWA, Dynamic OG, share/copy/download actions
- Playwright smoke coverage for hydration, runtime status, result-page in-place lookup, source switching, theme/language controls, null-array response tolerance, and DNSViz rendering

## Runtime Controls

Password auth:

```sh
WHOICE_AUTH_MODE=password
WHOICE_SITE_PASSWORD=change-me
```

Bearer/API token auth:

```sh
WHOICE_AUTH_MODE=token
WHOICE_API_TOKENS=token-one,token-two
```

Rate limit:

```sh
WHOICE_RATE_LIMIT_ENABLED=true
WHOICE_RATE_LIMIT_ANON=60/min
```

Metrics:

```sh
WHOICE_METRICS_ENABLED=true
```

DNS enrichment:

```sh
WHOICE_ENRICH_DNS=true
WHOICE_DNS_TIMEOUT=3s
WHOICE_ENRICH_DNSVIZ=true
```

WHOIS Web fallback:

```sh
WHOICE_WHOIS_WEB_ENABLED=true
```

EPP, registrar, and brand enrichment:

```sh
WHOICE_ENRICH_EPP=true
WHOICE_ENRICH_REGISTRAR=true
WHOICE_ENRICH_BRANDS=true
WHOICE_ENRICH_PRICING=false
WHOICE_ENRICH_MOZ=false
```

Brand map override:

```sh
mkdir -p data/brands
# edit data/brands/brand-map.json next to docker-compose.yml
```

Custom lookup servers are exposed through the Advanced panel in the Web UI and through the API parameters `rdap_server`, `whois_server`, and `whois_follow`. They remain blocked unless `WHOICE_ALLOW_CUSTOM_SERVERS=true` is set.
