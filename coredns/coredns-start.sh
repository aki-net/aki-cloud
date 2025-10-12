#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
CORE_CONF="$DATA_DIR/dns/Corefile"
ZONES_DIR="$DATA_DIR/dns/zones"
NODE_INFO="$DATA_DIR/cluster/node.json"

# Check if this node has NS IPs (is a nameserver node)
if [ -f "$NODE_INFO" ]; then
  HAS_NS_IPS=$(jq -r '.ns_ips | length > 0' "$NODE_INFO" 2>/dev/null || echo "false")
  if [ "$HAS_NS_IPS" != "true" ]; then
    echo "This node has no NS IPs - CoreDNS not needed. Sleeping..."
    sleep infinity
  fi
else
  echo "Node info not found at $NODE_INFO - waiting for initialization..."
  # Wait for node.json to be created
  while [ ! -f "$NODE_INFO" ]; do
    sleep 5
  done
  # Re-check after file is created
  exec "$0" "$@"
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
