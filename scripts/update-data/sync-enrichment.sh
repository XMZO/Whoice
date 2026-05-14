#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/enrichment"
EMBED="$ROOT/services/lookup-api/internal/data/enrichment/snapshots"

test -s "$SRC/moz.json"
mkdir -p "$EMBED"
cp "$SRC/moz.json" "$EMBED/moz.json"
