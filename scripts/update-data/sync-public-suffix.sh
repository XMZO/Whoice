#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/public-suffix"
EMBED="$ROOT/services/lookup-api/internal/data/publicsuffixes/snapshots"

test -s "$SRC/extra.dat"
mkdir -p "$EMBED"
cp "$SRC/extra.dat" "$EMBED/extra.dat"
if [ -s "$SRC/public_suffix_list.dat" ]; then
  cp "$SRC/public_suffix_list.dat" "$EMBED/public_suffix_list.dat"
fi
