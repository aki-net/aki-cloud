#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
CORE_CONF="$DATA_DIR/dns/Corefile"
ZONES_DIR="$DATA_DIR/dns/zones"

if [ "${ENABLE_COREDNS:-true}" != "true" ]; then
  echo "CoreDNS disabled on this node. Sleeping..."
  sleep infinity
fi

mkdir -p "$ZONES_DIR"

if [ ! -f "$CORE_CONF" ]; then
  cat <<'EOF' > "$CORE_CONF"
.:53 {
    log
    errors
}
EOF
fi

exec /coredns -conf "$CORE_CONF"
