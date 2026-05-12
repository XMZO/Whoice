#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/enrichment"
EMBED="$ROOT/services/lookup-api/internal/data/enrichment/snapshots"

test -s "$SRC/pricing.json"
test -s "$SRC/moz.json"
mkdir -p "$EMBED"
cp "$SRC/pricing.json" "$EMBED/pricing.json"
cp "$SRC/moz.json" "$EMBED/moz.json"
