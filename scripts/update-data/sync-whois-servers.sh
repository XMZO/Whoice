#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/packages/data/whois-servers"
EMBED="$ROOT/services/lookup-api/internal/data/whoisservers/snapshots"

test -s "$SRC/iana.json"
test -s "$SRC/extra.json"
mkdir -p "$EMBED"
cp "$SRC/iana.json" "$EMBED/iana.json"
cp "$SRC/extra.json" "$EMBED/extra.json"
