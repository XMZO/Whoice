#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/brands/brand-map.json"
EMBED="$ROOT/services/lookup-api/internal/data/brandmap/snapshots"

test -s "$SRC"
mkdir -p "$EMBED"
cp "$SRC" "$EMBED/brand-map.json"
