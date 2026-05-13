#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
OUT="$ROOT/packages/data/rdap-bootstrap"
EMBED="$ROOT/services/lookup-api/internal/data/rdapbootstrap/snapshots"
TMP="$OUT/.tmp"

mkdir -p "$OUT" "$TMP" "$EMBED"

fetch() {
  name="$1"
  url="$2"
  target="$OUT/$name.json"
  tmp="$TMP/$name.json"
  curl --fail --location --silent --show-error "$url" --output "$tmp"
  test -s "$tmp"
  mv "$tmp" "$target"
}

fetch dns https://data.iana.org/rdap/dns.json
fetch ipv4 https://data.iana.org/rdap/ipv4.json
fetch ipv6 https://data.iana.org/rdap/ipv6.json
fetch asn https://data.iana.org/rdap/asn.json

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "$OUT/manifest.json" <<EOF
{
  "generatedAt": "$generated_at",
  "sources": {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
    "asn": "https://data.iana.org/rdap/asn.json"
  },
  "sha256": {
    "dns": "$(sha256sum "$OUT/dns.json" | awk '{print $1}')",
    "ipv4": "$(sha256sum "$OUT/ipv4.json" | awk '{print $1}')",
    "ipv6": "$(sha256sum "$OUT/ipv6.json" | awk '{print $1}')",
    "asn": "$(sha256sum "$OUT/asn.json" | awk '{print $1}')"
  }
}
EOF

rm -rf "$TMP"
cp "$OUT/dns.json" "$EMBED/dns.json"
cp "$OUT/ipv4.json" "$EMBED/ipv4.json"
cp "$OUT/ipv6.json" "$EMBED/ipv6.json"
cp "$OUT/asn.json" "$EMBED/asn.json"
if [ -s "$OUT/extra.json" ]; then
  cp "$OUT/extra.json" "$EMBED/extra.json"
fi
