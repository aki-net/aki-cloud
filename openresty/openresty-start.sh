#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
CONF_DIR="$DATA_DIR/openresty"
SITES_DIR="$CONF_DIR/sites-enabled"
SENTINEL="$CONF_DIR/.reload"

mkdir -p "$SITES_DIR"
mkdir -p /var/log/nginx
mkdir -p "$(dirname "$SENTINEL")"
: > "$SENTINEL"

# Generate nginx.conf if missing
if [ ! -f "$CONF_DIR/nginx.conf" ]; then
  cat <<'EOF' > "$CONF_DIR/nginx.conf"
worker_processes 2;
error_log stderr warn;
events {
    worker_connections 4096;
}
http {
    access_log off;
    client_max_body_size 32M;
    default_type application/octet-stream;
    
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        ssl_certificate /data/openresty/default.crt;
        ssl_certificate_key /data/openresty/default.key;
        return 204;
    }
    
    include /data/openresty/sites-enabled/*.conf;
}
EOF
fi

# Generate default self-signed cert if missing
if [ ! -f "$CONF_DIR/default.crt" ] || [ ! -f "$CONF_DIR/default.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CONF_DIR/default.key" \
    -out "$CONF_DIR/default.crt" \
    -days 365 -subj "/CN=default"
fi

# Test config
nginx -t -c "$CONF_DIR/nginx.conf"

watch_reload() {
  local last_mtime="$(stat -c %Y "$SENTINEL" 2>/dev/null || echo "")"
  while true; do
    if [ -f "$SENTINEL" ]; then
      current_mtime="$(stat -c %Y "$SENTINEL" 2>/dev/null || echo "")"
      if [ -n "$current_mtime" ] && [ "$current_mtime" != "$last_mtime" ]; then
        last_mtime="$current_mtime"
        nginx -s reload >/dev/null 2>&1 || true
      fi
    fi
    sleep 2
  done
}

watch_reload &

# Start nginx
exec nginx -c "$CONF_DIR/nginx.conf" -g "daemon off;"
