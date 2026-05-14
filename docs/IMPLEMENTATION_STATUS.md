# Implementation Status

This audit compares the current repository with `PLAN.md`. The goal is to keep the phase boundary honest: Phase 0-5 are now closed to their planned acceptance bars, while compatibility and operations work can continue as normal maintenance.

## Phase Summary

| Plan phase | Status | Notes |
| --- | --- | --- |
| Phase 0: architecture skeleton | Done | Monorepo, Go API, Next.js Web, Docker Compose, schema files, unified model, plugin registry, and phase guardrails exist. |
| Phase 1: core lookup MVP | Done | Domain, IPv4, IPv6, ASN, and CIDR lookup are implemented through the normalizer, RDAP provider, parser, merger, `/api/lookup`, runtime API fixtures, and the basic Web result UI. WHOIS domain lookup, generic WHOIS parsing, raw evidence display, and provider traces are covered. Broader TLD edge compatibility belongs to Phase 3/ongoing maintenance, not the Phase 1 MVP bar. |
| Phase 2: experience layer | Done | Search history, keyboard shortcuts, theme, i18n, expanded API/runtime docs, PWA manifest/service worker, Dynamic OG, share menu, copy URL/raw/query, download JSON, and download OG image are implemented. |
| Phase 3: compatibility enhancement | Done for planned stage | TLD parser registry expansion, high-value rewritten PHP-parser coverage, WHOIS Web fallback framework, stable `.dz`/`.ni`/`.vn` API fallback modules, reserved/unregistered compatibility rules, embedded/mounted WHOIS server maps, manual RDAP/WHOIS server override, ICANN registrar CSV enrichment, and advanced server override UI are in place with tests/fixtures. More ccTLDs can still be added as compatibility maintenance, but they no longer block this phase. |
| Phase 4: optional enhancement | Done for planned stage | Fresh-first singleflight, no WHOIS/RDAP result cache, password/token auth, fixed-window rate limit, EPP explanations, DNS/DNSViz enrichment, ICANN registrar enrichment, registrar/NS brand enrichment, isolated optional Pricing source plumbing with Miqingju snapshot support and local fallback, and optional local Moz datasets are implemented as configurable lookup guards or enrichment pipeline steps. External pricing/Moz importers remain optional future integrations, not blockers for this phase. |
| Phase 5: productionization | Done for planned stage | Multi-arch GHCR release workflow, Docker image deploy path, CI, parser fixture tests, runtime API contract fixtures, reviewable validated data snapshots, scheduled data update workflow, trace IDs, structured request logs, admin status, public Web `/status` runtime inspector, Prometheus-style metrics with latency histograms, async observability reporters, desktop/mobile Playwright smoke tests, failure-state coverage, operations docs, and security docs are in place. |

## Implemented

- `unofficial/` is treated as reference-only and ignored by Git.
- Go lookup API serves `/api/health`, `/api/version`, `/api/capabilities`, and `/api/lookup`.
- Query normalization handles domains, URLs, IPv4, IPv6, ASN, and CIDR.
- RDAP provider supports domain, IPv4, IPv6, ASN, and CIDR via IANA RDAP bootstrap, with `rdap.org` fallback; endpoint routing is covered by provider tests.
- RDAP bootstrap resolution now uses mounted `data/rdap-bootstrap` files first, then embedded snapshots, then live IANA data as fallback.
- Reviewable `packages/data/rdap-bootstrap` and `packages/data/registrars` snapshots exist with manifests and are synchronized into embedded API snapshots.
- WHOIS provider supports TCP 43 with embedded/mounted TLD server data, second-level extra server data, query templates, referral follow, non-UTF-8 response decoding, and explicit `whois_follow=0` disable semantics.
- WHOIS server routing has offline tests for critical second-level suffixes and server-specific query templates; optional live TCP smoke checks can be enabled with `WHOICE_LIVE_WHOIS_SMOKE=1`.
- RDAP, generic WHOIS, UK, JP, FR, CN, BR, IT, EU, BE, PL, CZ, HU, SK, RO, DE, NL, CA, AU, SE/NU, FI, KR, AT, RU/SU, EE, BG, KG, TR, HK, TW, SI, UA, and ID WHOIS parsers feed a unified merger, with initial golden fixtures.
- WHOIS Web fallback is a separate provider plugin, not a runtime dependency on `unofficial/`; it currently has manual notice modules for selected TLDs plus API-backed `.dz`, `.ni`, and `.vn` modules based on the PHP reference behavior.
- Generic reserved/unregistered detection includes compatibility keywords from `unofficial/whois-domain-lookup`, with regression tests to avoid broad TLD-specific wording such as `.be` `NOT AVAILABLE` breaking registered domains.
- Lookup results are not cached; concurrent identical requests are coalesced in-process so only one live upstream lookup is made at a time.
- DNS enrichment resolves A/AAAA/CNAME/MX/NS for domain results.
- DNSViz link enrichment provides external DNSSEC/delegation diagnostics without adding lookup latency.
- ICANN registrar CSV enrichment is a separate module with embedded snapshot fallback and mounted `/data/registrars/icann-accredited-registrars.csv` override support.
- Password/token auth and fixed-window rate limit middleware exist for lookup requests.
- Custom RDAP/WHOIS server policy blocks private, loopback, link-local, multicast, and malformed targets by default.
- Lookup responses include an `X-Trace-ID` header, `result.meta.traceId`, and provider timing/debug trace in `result.meta.providers`.
- `/api/admin/status` exposes basic runtime stats and plugin/capability state.
- `/api/admin/status` includes lookup and provider-level counters.
- `/api/metrics` exposes Prometheus-style lookup/provider counters and latency histograms.
- Async observability reporter adapters support `log`, `webhook`, and combined modes for lookup summaries without caching results or blocking the response path.
- Web `/status` exposes health, version, capability, plugin, and same-origin endpoint visibility for self-hosted deployments without touching lookup freshness.
- Web supports theme selection, three locale options, PWA manifest/service worker with static shell assets, Dynamic OG image generation, local plugin renderer panels, keyboard shortcuts, a share/export menu, copy URL/query/raw actions, download JSON, download OG image, shared local search history from home and result pages, API docs, and an Advanced lookup panel for source server overrides and WHOIS referral depth.
- Domain result pages render DNS enrichment instead of an empty Network panel; IP/ASN/CIDR pages still render Network fields.
- EPP status enrichment covers the common ICANN/EPP client, server, pending, grace, and redemption states.
- Optional enrichment now runs through a lookup enrichment pipeline with per-step enablement, support checks, and warning-only failures so EPP, DNS, DNSViz, registrar CSV, brand, Pricing, and Moz do not become hard dependencies of the core lookup path.
- Optional registrar and nameserver brand enrichment exists with a mounted `data/brands/brand-map.json` override and embedded snapshot derived from Whoice defaults plus `unofficial/next-whois` UI-branding ideas.
- Optional Pricing enrichment is isolated behind a replaceable pricing source/resolver boundary with a Miqingju public snapshot source and mounted-or-embedded local JSON fallback; the public config remains only `pricing = true/false`. Optional Moz enrichment exists through mounted or embedded local JSON datasets.
- Next.js UI has search, result page, source mode switcher, local history, docs stub, and raw evidence panels.
- Compose defaults to prebuilt GHCR images and can be downloaded as a single `docker-compose.yml`; it mounts same-folder `./data`, uses an explicit bridge network, and includes service healthchecks.
- GitHub Actions workflow exists for `linux/amd64` and `linux/arm64` image publishing.
- OpenAPI and JSON Schema contract files exist; CI validates syntax, validates curated, parser-fixture, and runtime API response samples, regenerates TypeScript schema types, checks Web type compatibility, and checks Go model JSON fields against schema definitions.
- Runtime API contract fixtures now exercise RDAP domain success, WHOIS domain success, WHOIS Web fallback success, RDAP IPv4 success, RDAP IPv6 success, RDAP ASN success, RDAP CIDR success, and invalid-query errors through the real HTTP lookup path.
- RDAP parser and merger tests prevent RDAP HTTP error bodies from being treated as registered-domain evidence while still preserving raw data for debugging.
- `pnpm test:data` validates data manifests, hash integrity, parser/readability of data files, embedded snapshot sync, and critical PSL/WHOIS routing coverage.
- Singleflight result cloning preserves empty collection fields as JSON arrays, preventing schema-valid results from drifting into `null` arrays after coalescing.
- Plugin registry scaffold exists and `/api/version` reports plugin descriptors.
- `pnpm test:pre5` checks Phase 0-4 guardrails so the architecture skeleton, core lookup, experience layer, compatibility loop, and optional enhancement plugins cannot silently disappear.
- Playwright smoke tests cover hydration, runtime status visibility, result-page in-place lookup, source switching, theme/language controls, null-array response tolerance, DNSViz panel rendering, actionable lookup failure states, and mobile/touch layout overflow checks.
- `pnpm test:phase5` checks Phase 5 productionization guardrails so observability, reporters, status/metrics/admin endpoints, data update automation, runtime API fixtures, native multi-arch release workflow, Docker healthchecks, Playwright device coverage, and operations/security docs cannot silently disappear.

## Remaining Work Before Calling The Whole Plan Complete

- Ongoing compatibility maintenance: add more TLD parsers and WHOIS Web modules only when backed by real samples and fixtures.
- Ongoing production maintenance: harden authenticated admin surfaces once a safe browser auth flow is chosen. `/api/admin/config` is intentionally reserved and does not write config files yet.
- Ongoing production maintenance: continue release, deployment, rollback, browser, and security hardening as real deployments shake out edge cases.
- Optional future integrations: add external Pricing/Moz/importer jobs only if stable providers are chosen. Current Phase 4 local dataset enrichers are complete and do not call external APIs during lookup; pricing source swaps should plug into `internal/enrich/pricing` without adding provider-specific public config fields.

## Current Bar

The current repository now has Phase 0 architecture skeleton, Phase 1 core lookup MVP, Phase 2 experience layer, Phase 3 compatibility enhancement, Phase 4 optional enhancement, and Phase 5 productionization completed to their planned stage bars. Future work should move in this order:

1. Add compatibility extensions from `unofficial/` references only when backed by real samples and fixtures, rewriting the behavior into Whoice's parser/provider architecture instead of copying implementation code.
2. Expand the authenticated admin UI once a safe browser auth flow is chosen.
3. Continue production deployment/security documentation and release rollback hardening as deployments mature.
4. Add external enrichment importers only if stable providers are chosen.
