#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-/data}"
GEN_BIN="${BACKEND_GENERATOR_BIN:-/app/bin/generate}"
TEMPLATE="${COREDNS_TEMPLATE:-/app/coredns/Corefile.tmpl}"

if [ ! -x "$GEN_BIN" ]; then
  echo "generator binary not found: $GEN_BIN" >&2
  exit 1
fi

exec "$GEN_BIN" --data-dir "$DATA_DIR" --coredns-template "$TEMPLATE" coredns
