#!/usr/bin/env sh
set -eu

DATA_DIR="${DATA_DIR:-/data}"
CONF_DIR="$DATA_DIR/openresty"
SITES_DIR="$CONF_DIR/sites-enabled"

mkdir -p "$SITES_DIR"
mkdir -p /var/log/nginx

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

# Start nginx
exec nginx -c "$CONF_DIR/nginx.conf" -g "daemon off;"