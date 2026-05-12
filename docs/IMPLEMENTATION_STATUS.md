# Implementation Status

This audit compares the current repository with `PLAN.md`. The goal is not to soften the truth: Whoice is still an MVP, not the full plan.

## Phase Summary

| Plan phase | Status | Notes |
| --- | --- | --- |
| Phase 0: architecture skeleton | Mostly done | Monorepo, Go API, Next.js Web, Docker Compose, schema files, unified model, and plugin registry scaffold exist. |
| Phase 1: core lookup MVP | Partial | Domain/IP/ASN/CIDR RDAP works through IANA bootstrap with fallback; WHOIS domain works with common TLD resolver data; generic parsers, fixtures, merger, and provider trace exist. Broader parser confidence and many TLD edge cases are still missing. |
| Phase 2: experience layer | Partial | Search, result page, local history, docs stub, source switcher, theme, i18n base, PWA manifest/service worker, Dynamic OG, local result plugin renderers, and share/copy/download actions exist. Richer result workspace interactions are still missing. |
| Phase 3: compatibility enhancement | Partial | Initial UK/JP/FR/CN/BR/IT/EU/BE/PL/CZ/HU/SK/RO TLD parser migration, WHOIS Web fallback framework, embedded/mounted WHOIS server maps, ICANN registrar CSV enrichment, and advanced server override UI exist. Many ccTLD parsers and broader web fallback modules are still missing. |
| Phase 4: optional enhancement | Partial | EPP, DNS, DNSViz links, ICANN registrar metadata, registrar/NS brand enrichment, and optional local Pricing/Moz datasets exist; password/token auth and fixed-window rate limit exist. Lookup result caching was deliberately removed to preserve WHOIS/RDAP freshness. |
| Phase 5: productionization | Partial | Multi-arch GHCR release workflow, Docker image deploy path, CI, parser fixture tests, scheduled RDAP/registrar/brand/WHOIS-server data workflow, basic trace IDs, structured request logs, admin status, public Web `/status` runtime inspector, Prometheus-style metrics with latency histograms, Playwright smoke tests, and initial security docs exist. Broader browser/device coverage is still limited. |

## Implemented

- `unofficial/` is treated as reference-only and ignored by Git.
- Go lookup API serves `/api/health`, `/api/version`, `/api/capabilities`, and `/api/lookup`.
- Query normalization handles domains, URLs, IPv4, IPv6, ASN, and CIDR.
- RDAP provider supports domain, IP, ASN, and CIDR via IANA RDAP bootstrap, with `rdap.org` fallback.
- RDAP bootstrap resolution now uses mounted `data/rdap-bootstrap` files first, then embedded snapshots, then live IANA data as fallback.
- WHOIS provider supports TCP 43 with embedded/mounted TLD server data, second-level extra server data, query templates, referral follow, non-UTF-8 response decoding, and explicit `whois_follow=0` disable semantics.
- RDAP, generic WHOIS, UK, JP, FR, CN, BR, IT, EU, BE, PL, CZ, HU, SK, and RO WHOIS parsers feed a unified merger, with initial golden fixtures.
- WHOIS Web fallback is a separate provider plugin, not a runtime dependency on `unofficial/`; it currently has manual notice modules for selected TLDs and an API-backed `.vn` module based on the PHP reference behavior.
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
- Web `/status` exposes health, version, capability, plugin, and same-origin endpoint visibility for self-hosted deployments without touching lookup freshness.
- Web supports theme selection, three locale options, PWA manifest/service worker, Dynamic OG image generation, local plugin renderer panels, share URL, copy raw, download JSON actions, and an Advanced lookup panel for source server overrides and WHOIS referral depth.
- Domain result pages render DNS enrichment instead of an empty Network panel; IP/ASN/CIDR pages still render Network fields.
- EPP status enrichment covers the common ICANN/EPP client, server, pending, grace, and redemption states.
- Optional registrar and nameserver brand enrichment exists with a mounted `data/brands/brand-map.json` override and embedded snapshot derived from Whoice defaults plus `unofficial/next-whois` UI-branding ideas.
- Optional Pricing and Moz enrichment exists through mounted or embedded local JSON datasets; these modules do not call external APIs during lookup.
- Next.js UI has search, result page, source mode switcher, local history, docs stub, and raw evidence panels.
- Compose defaults to prebuilt GHCR images and can be downloaded as a single `docker-compose.yml`; it mounts same-folder `./data`, uses an explicit bridge network, and includes service healthchecks.
- GitHub Actions workflow exists for `linux/amd64` and `linux/arm64` image publishing.
- OpenAPI and JSON Schema contract files exist; CI validates syntax, validates curated, parser-fixture, and runtime API response samples, regenerates TypeScript schema types, checks Web type compatibility, and checks Go model JSON fields against schema definitions.
- Plugin registry scaffold exists and `/api/version` reports plugin descriptors.
- Playwright smoke tests cover hydration, runtime status visibility, result-page in-place lookup, source switching, theme/language controls, null-array response tolerance, and DNSViz panel rendering.

## Must Close Before Calling It Plan-Complete

- Expand schema runtime validation from parser fixtures to broader live/API smoke fixtures beyond the initial deterministic runtime response.
- Expand embedded RDAP bootstrap snapshot coverage and keep it refreshed through release automation.
- Continue validating WHOIS server snapshots against live lookup smoke cases and expand server-specific query templates.
- Continue migrating high-value TLD parsers from `unofficial/whois-domain-lookup` with fixtures for each one.
- Expand WHOIS Web fallback modules beyond notices and `.vn`, with isolated tests for each remote format.
- Expand observability beyond provider trace, counters, and latency histograms to external reporter adapters.
- Add richer result workspace interactions beyond the current local plugin renderer boundary.
- Expand the runtime status surface with authenticated admin stats when a safe UI auth flow exists.
- Continue validating scheduled data update workflows and add external enrichment importers if stable providers are chosen.
- Broaden Playwright coverage beyond smoke paths, including mobile-specific layout assertions and failure states.

## Current Bar

The current repository is acceptable as a Phase 0 plus early Phase 1 scaffold. It is not acceptable to claim the full `PLAN.md` is implemented. Future work should move in this order:

1. Finish contract/schema validation and fixture infrastructure.
2. Strengthen RDAP/WHOIS data source correctness.
3. Add security, auth, and rate-limit plugins.
4. Continue migrating compatibility value from `unofficial/whois-domain-lookup`, especially TLD-specific parsers and web fallback providers.
5. Bring the UI up to the planned modern product level from `unofficial/next-whois` plus Whoice's own result workspace ideas.
