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
worker_processes auto;
worker_rlimit_nofile 524288;
error_log stderr warn;

events {
    use epoll;
    multi_accept on;
    worker_connections 8192;
}

http {
    include       /usr/local/openresty/nginx/conf/mime.types;
    default_type  application/octet-stream;
    server_tokens off;
    real_ip_recursive on;
    access_log off;

    map $http_x_forwarded_for $client_real_ip {
        ""                         $remote_addr;
        ~^\s*(?P<first>[^,\s]+).*  $first;
    }

    map $http_x_forwarded_for $edge_forwarded_for {
        ""      $client_real_ip;
        default $http_x_forwarded_for;
    }

    limit_req_status 429;
    limit_conn_status 429;
    limit_req_log_level warn;
    limit_conn_log_level warn;
    limit_req_zone $client_real_ip zone=edge_req_per_ip:32m rate=120r/s;
    limit_req_zone $server_name zone=edge_req_per_host:32m rate=8000r/s;
    limit_conn_zone $client_real_ip zone=edge_conn_per_ip:16m;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;

    reset_timedout_connection on;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 30s;
    keepalive_timeout 30s;
    keepalive_requests 1000;
    lingering_timeout 15s;
    client_body_buffer_size 16k;
    client_max_body_size 64m;
    large_client_header_buffers 4 16k;

    proxy_buffering on;
    proxy_buffers 16 16k;
    proxy_buffer_size 32k;
    proxy_busy_buffers_size 64k;
    proxy_temp_file_write_size 64k;
    proxy_max_temp_file_size 0;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    server {
        listen 80 default_server;
        listen 443 ssl http2 default_server;
        server_name _;
        ssl_certificate /data/openresty/default.crt;
        ssl_certificate_key /data/openresty/default.key;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        ssl_protocols TLSv1.2 TLSv1.3;
        limit_conn edge_conn_per_ip 200;

        location / {
            return 204;
        }
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
