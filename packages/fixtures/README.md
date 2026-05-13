# Fixtures

Parser and lookup fixtures live here. Every migrated parser should add at least one raw response fixture and one expected JSON fixture.

Current fixture families:

- `whois/generic`: generic WHOIS parser regression cases.
- `rdap/domain`: RDAP domain parser regression cases.
- `whois/<tld>`: TLD-specific WHOIS parser raw/expected golden fixtures.
- `api-runtime/*.response.json`: deterministic full HTTP API responses produced through the real normalizer, provider dispatch, parser registry, merger, and HTTP envelope. These fixtures cover RDAP domain, WHOIS domain, WHOIS Web fallback, RDAP IPv4, and invalid-query responses for schema drift detection.
