#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/icp-suffixes/icp-suffixes.json"
EMBED="$ROOT/services/lookup-api/internal/data/icpsuffixes/snapshots"

test -s "$SRC"
mkdir -p "$EMBED"
cp "$SRC" "$EMBED/icp-suffixes.json"
