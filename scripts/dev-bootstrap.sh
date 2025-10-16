#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_CMD="${COMPOSE:-docker compose}"
read -r -a COMPOSE_ARR <<<"$COMPOSE_CMD"
compose() {
  "${COMPOSE_ARR[@]}" "$@"
}

DATA_DIR="$ROOT_DIR/data"
ENV_FILE="$ROOT_DIR/.env"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

for cmd in docker curl jq openssl sha256sum; do
  require_command "$cmd"
done
if ! command -v python3 >/dev/null 2>&1 && ! command -v uuidgen >/dev/null 2>&1; then
  echo "Either python3 or uuidgen must be available" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo ".env not found. Copy env-example to .env and configure it before running make dev." >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

BACKEND_PORT="${BACKEND_PORT:-8080}"
NODE_NAME="${NODE_NAME:-node-1}"
NS_LABEL="${NS_LABEL:-dns}"
NS_BASE_DOMAIN="${NS_BASE_DOMAIN:-aki.cloud}"
API_BASE="http://127.0.0.1:${BACKEND_PORT}"

log() {
  printf '==> %s\n' "$1"
}

compute_node_id() {
  local secret="$1"
  local name="$2"
  local lower_name
  lower_name=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
  local hash
  hash=$(printf '%s:%s' "$secret" "$lower_name" | sha256sum | awk '{print $1}')
  printf '%s-%s-%s-%s-%s\n' "${hash:0:8}" "${hash:8:4}" "${hash:12:4}" "${hash:16:4}" "${hash:20:12}"
}

generate_uuid() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
  elif command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
  fi
}

generate_bcrypt() {
  local password="$1"
  local hash
  if hash="$(python3 - "$password" <<'PY'
import bcrypt
import sys
password = sys.argv[1].encode()
print(bcrypt.hashpw(password, bcrypt.gensalt(rounds=10)).decode())
PY
  )"; then
    printf '%s\n' "$hash"
    return 0
  fi
  hash="$(docker run --rm httpd:2.4-alpine htpasswd -nbB temp "$password" | cut -d: -f2)" || return 1
  printf '%s\n' "$hash"
}

update_env_node_id() {
  local node_id="$1"
  local tmp
  tmp=$(mktemp)
  awk -v id="$node_id" '
    BEGIN {updated = 0}
    /^NODE_ID=/ {print "NODE_ID=" id; updated = 1; next}
    {print}
    END {if (updated == 0) print "NODE_ID=" id}
  ' "$ENV_FILE" >"$tmp"
  mv "$tmp" "$ENV_FILE"
}

wait_for_backend() {
  local attempts=0
  local max_attempts=60
  while ((attempts < max_attempts)); do
    if curl -fsS "${API_BASE}/readyz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    attempts=$((attempts + 1))
  done
  echo "Backend did not become ready after ${max_attempts} seconds" >&2
  return 1
}

create_node() {
  local payload tmp status
  payload="$(cat)"
  tmp=$(mktemp)
  status=$(curl -sS -o "$tmp" -w "%{http_code}" \
    -X POST "${API_BASE}/api/v1/admin/nodes" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload")
  if [[ "$status" != "201" && "$status" != "200" ]]; then
    echo "Failed to create node (HTTP ${status}): $(cat "$tmp")" >&2
    rm -f "$tmp"
    exit 1
  fi
  rm -f "$tmp"
}

log "Stopping existing stack (if running)..."
if ! compose down -v --remove-orphans >/dev/null 2>&1; then
  log "Compose down reported non-zero exit status; continuing."
fi

if [ -d "$DATA_DIR" ]; then
  log "Clearing existing data directory..."
  if ! compose run --rm --no-deps --entrypoint sh backend -c 'rm -rf /data/*' >/dev/null 2>&1; then
    log "Compose run cleanup failed; falling back to host removal."
  fi
  rm -rf "$DATA_DIR"
fi
mkdir -p "$DATA_DIR"

log "Generating fresh cluster secrets..."
CLUSTER_SECRET="$(openssl rand -hex 32)"
JWT_SECRET="$(openssl rand -hex 32)"
mkdir -p "$DATA_DIR/cluster" "$DATA_DIR/domains" "$DATA_DIR/users" "$DATA_DIR/infra" "$DATA_DIR/extensions"
printf '%s\n' "$CLUSTER_SECRET" >"$DATA_DIR/cluster/secret"
printf '%s\n' "$JWT_SECRET" >"$DATA_DIR/cluster/jwt_secret"
chmod 600 "$DATA_DIR/cluster/secret" "$DATA_DIR/cluster/jwt_secret"

LOCAL_NODE_ID="$(compute_node_id "$CLUSTER_SECRET" "$NODE_NAME")"
update_env_node_id "$LOCAL_NODE_ID"

cat >"$DATA_DIR/cluster/node.json" <<EOF
{
  "name": "$NODE_NAME",
  "node_id": "$LOCAL_NODE_ID",
  "ips": [],
  "ns_ips": [],
  "edge_ips": [],
  "ns_label": "$NS_LABEL",
  "ns_base_domain": "$NS_BASE_DOMAIN",
  "api_endpoint": "$API_BASE",
  "labels": ["dev"],
  "roles": []
}
EOF
printf '{"peers":[]}\n' >"$DATA_DIR/cluster/peers.json"
printf '[]\n' >"$DATA_DIR/infra/nameserver_status.json"

log "Creating default users..."
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
ADMIN_HASH="$(generate_bcrypt "test123")"
USER_HASH="$(generate_bcrypt "test123")"
cat >"$DATA_DIR/users/users.json" <<EOF
[
  {
    "id": "admin",
    "email": "admin@aki.cloud",
    "role": "admin",
    "password": "$ADMIN_HASH",
    "created_at": "$TIMESTAMP",
    "updated_at": "$TIMESTAMP"
  },
  {
    "id": "user",
    "email": "user@aki.cloud",
    "role": "user",
    "password": "$USER_HASH",
    "created_at": "$TIMESTAMP",
    "updated_at": "$TIMESTAMP"
  }
]
EOF
chmod 600 "$DATA_DIR/users/users.json"

log "Starting dev stack..."
compose up --build -d

log "Waiting for backend readiness..."
wait_for_backend

fetch_admin_token() {
  curl -sS -X POST "${API_BASE}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@aki.cloud","password":"test123"}' | jq -r '.token'
}

ADMIN_TOKEN="$(fetch_admin_token || true)"
if [[ -z "${ADMIN_TOKEN}" || "${ADMIN_TOKEN}" == "null" ]]; then
  log "Admin login failed, restarting backend to sync user store..."
  compose restart backend
  wait_for_backend
  ADMIN_TOKEN="$(fetch_admin_token || true)"
  if [[ -z "${ADMIN_TOKEN}" || "${ADMIN_TOKEN}" == "null" ]]; then
    echo "Unable to obtain admin token after backend restart." >&2
    exit 1
  fi
fi

log "Seeding demo nodes..."
log "  -> Local node (${NODE_NAME})"
create_node <<EOF
{
  "id": "$LOCAL_NODE_ID",
  "name": "$NODE_NAME",
  "ips": ["127.0.0.1"],
  "ns_ips": [],
  "edge_ips": ["127.0.0.1"],
  "api_endpoint": "$API_BASE",
  "labels": ["dev", "local"]
}
EOF

REMOTE_NODE1_ID="$(generate_uuid)"
log "  -> Remote node dev-edge-west"
create_node <<EOF
{
  "id": "$REMOTE_NODE1_ID",
  "name": "dev-edge-west",
  "ips": ["192.0.2.10", "192.0.2.53"],
  "ns_ips": ["192.0.2.53"],
  "edge_ips": ["192.0.2.10"],
  "api_endpoint": "http://192.0.2.10:8080",
  "labels": ["dev", "edge", "west"]
}
EOF

REMOTE_NODE2_ID="$(generate_uuid)"
log "  -> Remote node dev-edge-east"
create_node <<EOF
{
  "id": "$REMOTE_NODE2_ID",
  "name": "dev-edge-east",
  "ips": ["198.51.100.10", "198.51.100.53"],
  "ns_ips": ["198.51.100.53"],
  "edge_ips": ["198.51.100.10"],
  "api_endpoint": "http://198.51.100.10:8080",
  "labels": ["dev", "edge", "east"]
}
EOF

log "Seeding demo domains and TLS scenarios..."
API_BASE="$API_BASE" "$ROOT_DIR/seed-demo-data.sh"

log "Dev stack is ready."
cat <<EOF

Login credentials:
  Admin: admin@aki.cloud / test123
  User : user@aki.cloud / test123

Sample nodes:
  - $NODE_NAME (local)
  - dev-edge-west (remote)
  - dev-edge-east (remote)

Sample domains seeded via ./seed-demo-data.sh.
EOF
