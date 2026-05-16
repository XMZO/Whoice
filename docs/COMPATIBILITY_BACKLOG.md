# Compatibility Backlog

This note tracks parser and provider coverage ideas learned from external
WHOIS/RDAP tools. Use it as a checklist only: implementations in Whoice should
be rewritten around the local Go providers, parser fixtures, and API schema.

## High-value parser fixtures

Add fixtures before adding parser code whenever possible.

- RDAP: reserved labels via `variants.relations=RESTRICTED_REGISTRATION`.
- RDAP: registrar entities with string `roles`, nested abuse entities, `publicIds`,
  `port43`, entity `url`, and non-RDAP website links.
- RDAP: ccTLD-specific date actions such as `record expires`, `soft expiration`,
  and registrar expiration variants.
- WHOIS: availability/reserved wording for ccTLDs where the response is mostly a
  sentence instead of key-value data.
- WHOIS: status blocks split across multiple lines, especially `.kz`, `.uk`,
  `.ua`, `.fr`, `.it`, `.be`, `.md`, `.lu`, and `.lv`.
- WHOIS: registry-provided nameserver addresses, such as `.kz` primary/secondary
  server IP fields.

## WHOIS Web candidates

Prefer stable JSON or single-page HTML endpoints. Avoid fragile multi-step form
flows until there are fixtures and clear error behavior.

- Implemented: `.dz`, `.lk`, `.mt`, `.ni`, `.pa`, `.vn`.
- Notice-only/manual: `.ao`, `.az`, `.ba`, `.cy`, `.dj`, `.gq`, `.py`.
- Good future candidates: `.bb`, `.bo`, `.bt`, `.cu`, `.gr`, `.gt`, `.gw`,
  `.hu`, `.jo`, `.np`, `.ph`, `.tt`.
- Needs extra care: endpoints requiring CSRF cookies, view-state forms, captcha,
  or registry pages with no machine-readable response.

## Product ideas

- Raw WHOIS linkification for URLs and emails without inserting visible
  truncation markers.
- Collapsible RDAP JSON evidence view that keeps the result slot height stable.
- Local search history grouped by query type: domain, IPv4, IPv6, ASN, CIDR.
- Optional result sharing image endpoint, using Whoice's own result schema.
- Registrar and nameserver brand assets as a replaceable data pack.

## Implemented parser checklist

- Generic/domain-major: `.com` style WHOIS and generic RDAP.
- ccTLD parser fixtures: `.am`, `.at`, `.au`, `.ax`, `.bd`, `.be`, `.bg`,
  `.bn`, `.br`, `.ca`, `.cn`, `.cz`, `.de`, `.ee`, `.eu`, `.fi`, `.fr`,
  `.gg`, `.hk`, `.hu`, `.id`, `.il`, `.it`, `.je`, `.jp`, `.kg`, `.kr`,
  `.kz`, `.lt`, `.lu`, `.lv`, `.md`, `.mo`, `.mx`, `.nl`, `.pl`, `.pt`,
  `.qa`, `.ro`, `.rs`, `.ru`, `.se`, `.si`, `.sk`, `.st`, `.tn`, `.tr`,
  `.tw`, `.ua`, `.uz`.

## Parser candidates still worth checking

- Lower-risk key-value variants: `.ar`, `.cl`, `.cr`, `.im`, `.ls`, `.mk`,
  `.mw`, `.nc`, `.pf`, `.sm`, `.tg`, `.tm`, `.ve`.
- More complex or web-heavy formats: `.bb`, `.bo`, `.bt`, `.cu`, `.gr`,
  `.gt`, `.gw`, `.jo`, `.np`, `.ph`, `.tt`.
