#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
CORE_CONF="$DATA_DIR/dns/Corefile"
SENTINEL="$DATA_DIR/dns/.reload"

if [ -f "$CORE_CONF" ]; then
  touch "$CORE_CONF"
fi

if [ -n "$SENTINEL" ]; then
  mkdir -p "$(dirname "$SENTINEL")"
  date +%s > "$SENTINEL"
fi

exit 0
