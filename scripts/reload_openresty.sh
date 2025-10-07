#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
SENTINEL="$DATA_DIR/openresty/.reload"

mkdir -p "$(dirname "$SENTINEL")"
date +%s > "$SENTINEL"

exit 0
