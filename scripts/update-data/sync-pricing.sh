#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/pricing"
EMBED="$ROOT/services/lookup-api/internal/enrich/pricing/snapshots"

test -s "$SRC/pricing.json"
mkdir -p "$EMBED"
cp "$SRC/pricing.json" "$EMBED/pricing.json"
