#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
OUT="$ROOT/packages/data/public-suffix"
EMBED="$ROOT/services/lookup-api/internal/data/publicsuffixes/snapshots"
TMP="$OUT/.tmp"
URL="${WHOICE_PSL_URL:-https://publicsuffix.org/list/public_suffix_list.dat}"

mkdir -p "$OUT" "$EMBED" "$TMP"

target="$OUT/public_suffix_list.dat"
tmp="$TMP/public_suffix_list.dat"
curl --fail --location --silent --show-error "$URL" --output "$tmp"
test -s "$tmp"
grep -q "BEGIN ICANN DOMAINS" "$tmp"
grep -q "BEGIN PRIVATE DOMAINS" "$tmp"
grep -qx "com" "$tmp"
mv "$tmp" "$target"

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "$OUT/manifest.json" <<EOF
{
  "generatedAt": "$generated_at",
  "sources": {
    "publicSuffixList": "$URL"
  },
  "sha256": {
    "publicSuffixList": "$(sha256sum "$target" | awk '{print $1}')"
  }
}
EOF

rm -rf "$TMP"
cp "$target" "$EMBED/public_suffix_list.dat"
if [ -s "$OUT/extra.dat" ]; then
  cp "$OUT/extra.dat" "$EMBED/extra.dat"
fi
