#!/usr/bin/env bash
set -euo pipefail

CACHE_DIR="${CACHE_DIR:-/data/openresty/cache}"

case "$CACHE_DIR" in
  ""|"/"|"." )
    echo "Refusing to purge unsafe cache dir: '$CACHE_DIR'" >&2
    exit 1
    ;;
esac

if [[ ! -d "$CACHE_DIR" ]]; then
  mkdir -p "$CACHE_DIR"
  echo "Created cache directory $CACHE_DIR"
  exit 0
fi

find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
echo "Purged edge cache at $CACHE_DIR"
