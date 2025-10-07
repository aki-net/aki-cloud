#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
CORE_CONF="$DATA_DIR/dns/Corefile"

if [ -f "$CORE_CONF" ]; then
  touch "$CORE_CONF"
fi

exit 0
