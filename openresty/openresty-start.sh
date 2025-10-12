#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
CONF_DIR="$DATA_DIR/openresty"
SITES_DIR="$CONF_DIR/sites-enabled"
NODE_INFO="$DATA_DIR/cluster/node.json"

# Check if this node has edge IPs (is an edge node)
if [ -f "$NODE_INFO" ]; then
  HAS_EDGE_IPS=$(jq -r '.edge_ips | length > 0' "$NODE_INFO" 2>/dev/null || echo "false")
  if [ "$HAS_EDGE_IPS" != "true" ]; then
    echo "This node has no edge IPs - OpenResty not needed. Sleeping..."
    sleep infinity
  fi
else
  echo "Node info not found at $NODE_INFO - waiting for initialization..."
  # Wait for node.json to be created
  while [ ! -f "$NODE_INFO" ]; do
    sleep 5
  done
  # Restart this script now that node.json exists
  exec "$0" "$@"
fi

mkdir -p "$SITES_DIR"
mkdir -p /var/log/nginx

if [ ! -f "$CONF_DIR/nginx.conf" ]; then
  cat <<'EOF' > "$CONF_DIR/nginx.conf"
worker_processes 1;
events {
    worker_connections 1024;
}
http {
    include /usr/local/openresty/nginx/conf/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
}
EOF
fi

openresty -t -c "$CONF_DIR/nginx.conf" || {
  echo "initial nginx configuration test failed" >&2
}

inotifywait -mq -e modify,create,delete,move "$CONF_DIR" "$SITES_DIR" 2>/dev/null |
while read -r _ _ _; do
  openresty -s reload -c "$CONF_DIR/nginx.conf" 2>/dev/null || true
done &

trap 'openresty -s quit -c "$CONF_DIR/nginx.conf" 2>/dev/null || true; exit 0' INT TERM

exec openresty -g 'daemon off;' -c "$CONF_DIR/nginx.conf"
