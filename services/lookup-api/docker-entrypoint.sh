#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
  mkdir -p /data
  chown -R whoice:whoice /data 2>/dev/null || true
  exec su-exec whoice "$@"
fi

exec "$@"
