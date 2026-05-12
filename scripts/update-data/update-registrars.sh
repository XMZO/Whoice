#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
OUT="$ROOT/packages/data/registrars"
EMBED="$ROOT/services/lookup-api/internal/data/registrars/snapshots"
TMP="$OUT/.tmp"
URL="https://www.icann.org/en/contracted-parties/accredited-registrars/list-of-accredited-registrars/csvdownload"

mkdir -p "$OUT" "$EMBED" "$TMP"

target="$OUT/icann-accredited-registrars.csv"
tmp="$TMP/icann-accredited-registrars.csv"
curl --fail --location --silent --show-error "$URL" --output "$tmp"
test -s "$tmp"
head -n 1 "$tmp" | grep -q "Registrar Name"
mv "$tmp" "$target"

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "$OUT/manifest.json" <<EOF
{
  "generatedAt": "$generated_at",
  "sources": {
    "icannAccreditedRegistrars": "$URL"
  },
  "sha256": {
    "icannAccreditedRegistrars": "$(sha256sum "$target" | awk '{print $1}')"
  }
}
EOF

rm -rf "$TMP"
cp "$target" "$EMBED/icann-accredited-registrars.csv"
