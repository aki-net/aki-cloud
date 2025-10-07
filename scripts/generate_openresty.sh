#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-/data}"
GEN_BIN="${BACKEND_GENERATOR_BIN:-/app/bin/generate}"
NGINX_TEMPLATE="${NGINX_TEMPLATE:-/app/openresty/nginx.conf.tmpl}"
SITES_TEMPLATE="${SITES_TEMPLATE:-/app/openresty/sites.tmpl}"
OUTPUT_DIR="${OPENRESTY_OUTPUT:-${DATA_DIR}/openresty}"

if [ ! -x "$GEN_BIN" ]; then
  echo "generator binary not found: $GEN_BIN" >&2
  exit 1
fi

exec "$GEN_BIN" --data-dir "$DATA_DIR" --nginx-template "$NGINX_TEMPLATE" --sites-template "$SITES_TEMPLATE" --openresty-output "$OUTPUT_DIR" openresty
