#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
CORE_CONF="$DATA_DIR/dns/Corefile"
ZONES_DIR="$DATA_DIR/dns/zones"
SENTINEL="$DATA_DIR/dns/.reload"

mkdir -p "$ZONES_DIR"
mkdir -p "$(dirname "$SENTINEL")"
: > "$SENTINEL"

if [ ! -f "$CORE_CONF" ]; then
  cat <<'EOF' > "$CORE_CONF"
.:53 {
    log
    errors
}
EOF
fi

watch_reload() {
  local last_mtime="$(stat -c %Y "$SENTINEL" 2>/dev/null || echo "")"
  while true; do
    if [ -f "$SENTINEL" ]; then
      current_mtime="$(stat -c %Y "$SENTINEL" 2>/dev/null || echo "")"
      if [ -n "$current_mtime" ] && [ "$current_mtime" != "$last_mtime" ]; then
        last_mtime="$current_mtime"
        if pid=$(pidof coredns 2>/dev/null); then
          kill -USR1 "$pid" 2>/dev/null || true
        fi
      fi
    fi
    sleep 2
  done
}

watch_reload &

exec /coredns -conf "$CORE_CONF"
