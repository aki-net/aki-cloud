#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
DATA_DIR="$PROJECT_DIR/data"

MODE=""
NODE_NAME=""
NODE_ID=""
IPS=""
NS_IPS=""
NS_LABEL=""
NS_BASE_DOMAIN=""
SEED=""
ADMIN_EMAIL=""
ADMIN_PASS=""
ADMIN_PASS_FILE=""
ENABLE_COREDNS="auto"
ENABLE_OPENRESTY="auto"
FRONTEND_PORT="3000"
BACKEND_PORT="8080"
SECRETS_SUPPLIED=""
JWT_SECRET_INPUT=""

REPO_URL="${REPO_URL:-https://github.com/aki-net/aki-cloud.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/aki-cloud}"
SYSTEM_USER="${SYSTEM_USER:-akicloud}"
SKIP_BOOTSTRAP="${SKIP_BOOTSTRAP:-0}"

declare -a RERUN_ARGS=()

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --mode fresh|join          Set installation mode (fresh cluster or join)
  --node-name NAME           Node name identifier
  --ips ip1,ip2              Comma-separated list of all host IPs
  --ns-ips ip1,ip2           Comma-separated list of IPs acting as nameservers
  --ns-label LABEL           Nameserver label (default: dns)
  --ns-base-domain DOMAIN    Base domain for NS hostnames
  --seed HOST                Seed backend base URL (join mode)
  --admin-email EMAIL        Initial admin email (fresh)
  --admin-pass PASS          Initial admin password (fresh)
  --admin-pass-file PATH     Read admin password from file (fresh)
  --enable-coredns true|false  Force CoreDNS service state
  --enable-openresty true|false Force OpenResty service state
  --backend-port PORT        Backend API port (default 8080)
  --frontend-port PORT       Frontend port (default 3000)
  --cluster-secret VALUE     Pre-existing cluster secret (join)
  --jwt-secret VALUE         Pre-existing JWT secret (join)
  --repo-url URL             Git repository to clone (default: https://github.com/aki-net/aki-cloud.git)
  --install-dir PATH         Target installation directory (default: /opt/aki-cloud)
  --system-user USER         System user to own the deployment (default: akicloud)
  -h, --help                 Show this help text
EOF
}

abort() {
  echo "ERROR: $1" >&2
  exit 1
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    abort "Required command '$1' not found"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        MODE="$2"
        RERUN_ARGS+=(--mode "$2")
        shift 2 ;;
      --node-name)
        NODE_NAME="$2"
        RERUN_ARGS+=(--node-name "$2")
        shift 2 ;;
      --node-id)
        NODE_ID="$2"
        RERUN_ARGS+=(--node-id "$2")
        shift 2 ;;
      --ips)
        IPS="$2"
        RERUN_ARGS+=(--ips "$2")
        shift 2 ;;
      --ns-ips)
        NS_IPS="$2"
        RERUN_ARGS+=(--ns-ips "$2")
        shift 2 ;;
      --ns-label)
        NS_LABEL="$2"
        RERUN_ARGS+=(--ns-label "$2")
        shift 2 ;;
      --ns-base-domain)
        NS_BASE_DOMAIN="$2"
        RERUN_ARGS+=(--ns-base-domain "$2")
        shift 2 ;;
      --seed)
        SEED="$2"
        RERUN_ARGS+=(--seed "$2")
        shift 2 ;;
      --admin-email)
        ADMIN_EMAIL="$2"
        RERUN_ARGS+=(--admin-email "$2")
        shift 2 ;;
      --admin-pass)
        ADMIN_PASS="$2"
        RERUN_ARGS+=(--admin-pass "$2")
        shift 2 ;;
      --admin-pass-file)
        ADMIN_PASS_FILE="$2"
        RERUN_ARGS+=(--admin-pass-file "$2")
        shift 2 ;;
      --enable-coredns)
        ENABLE_COREDNS="$2"
        RERUN_ARGS+=(--enable-coredns "$2")
        shift 2 ;;
      --enable-openresty)
        ENABLE_OPENRESTY="$2"
        RERUN_ARGS+=(--enable-openresty "$2")
        shift 2 ;;
      --backend-port)
        BACKEND_PORT="$2"
        RERUN_ARGS+=(--backend-port "$2")
        shift 2 ;;
      --frontend-port)
        FRONTEND_PORT="$2"
        RERUN_ARGS+=(--frontend-port "$2")
        shift 2 ;;
      --cluster-secret)
        SECRETS_SUPPLIED="$2"
        RERUN_ARGS+=(--cluster-secret "$2")
        shift 2 ;;
      --jwt-secret)
        JWT_SECRET_INPUT="$2"
        RERUN_ARGS+=(--jwt-secret "$2")
        shift 2 ;;
      --repo-url)
        REPO_URL="$2"
        shift 2 ;;
      --install-dir)
        INSTALL_DIR="$2"
        RERUN_ARGS+=(--install-dir "$2")
        shift 2 ;;
      --system-user)
        SYSTEM_USER="$2"
        RERUN_ARGS+=(--system-user "$2")
        shift 2 ;;
      --skip-bootstrap)
        SKIP_BOOTSTRAP="1"
        shift ;;
      -h|--help)
        usage
        exit 0 ;;
      *)
        abort "Unknown option $1" ;;
    esac
  done
}

log() {
  echo "[install] $1"
}

install_base_packages() {
  log "Installing base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    ca-certificates \
    curl \
    git \
    gnupg \
    lsb-release \
    make \
    openssl \
    python3 \
    python3-venv \
    sudo \
    wget
}

install_docker_packages() {
  if command -v docker >/dev/null 2>&1; then
    return
  fi
  log "Installing Docker Engine"
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg
  local codename
  codename="$(lsb_release -cs)"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $codename stable" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable docker >/dev/null 2>&1 || true
  systemctl start docker
}

ensure_system_user() {
  if ! id "$SYSTEM_USER" >/dev/null 2>&1; then
    log "Creating system user $SYSTEM_USER"
    useradd -m -s /bin/bash "$SYSTEM_USER"
  fi
  usermod -aG docker "$SYSTEM_USER"
}

clone_or_update_repo() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating repository in $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --all --prune
    local current_branch
    current_branch="$(git -C "$INSTALL_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
    git -C "$INSTALL_DIR" checkout "$current_branch"
    git -C "$INSTALL_DIR" reset --hard "origin/$current_branch"
  else
    log "Cloning repository $REPO_URL into $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
  fi
  chown -R "$SYSTEM_USER":"$SYSTEM_USER" "$INSTALL_DIR"
}

maybe_bootstrap() {
  if [[ "$SKIP_BOOTSTRAP" == "1" ]]; then
    return
  fi

  local repo_present="0"
  if [[ -f "$PROJECT_DIR/docker-compose.yml" && -d "$PROJECT_DIR/backend" ]]; then
    repo_present="1"
  fi

  if command -v docker >/dev/null 2>&1 && [[ "$repo_present" == "1" ]]; then
    return
  fi

  if [[ $EUID -ne 0 ]]; then
    abort "Bootstrap requires root privileges. Re-run the installer as root."
  fi

  install_base_packages
  install_docker_packages
  ensure_system_user
  clone_or_update_repo

  log "Re-executing installer as $SYSTEM_USER"
  exec sudo -H -u "$SYSTEM_USER" env \
    SKIP_BOOTSTRAP=1 \
    INSTALL_DIR="$INSTALL_DIR" \
    SYSTEM_USER="$SYSTEM_USER" \
    "$INSTALL_DIR/install.sh" "${RERUN_ARGS[@]}"
}

prompt_if_empty() {
  local var_name="$1"
  local prompt_text="$2"
  local current="${!var_name}"
  if [[ -z "$current" ]]; then
    read -r -p "$prompt_text: " value
    eval "$var_name=\$value"
  fi
}

prompt_secret_if_empty() {
  local var_name="$1"
  local prompt_text="$2"
  local current="${!var_name}"
  if [[ -z "$current" ]]; then
    read -r -s -p "$prompt_text: " value
    echo
    eval "$var_name=\$value"
  fi
}

normalize_csv() {
  local input="$1"
  echo "$input" | tr ' ' '\n' | tr ',' '\n' | awk 'NF' | paste -sd',' -
}

generate_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    python3 -c 'import uuid; print(uuid.uuid4())'
  fi
}

generate_secret() {
  openssl rand -hex 32
}

write_file_atomic() {
  local path="$1"
  local content="$2"
  local tmp="$path.tmp$$"
  printf '%s' "$content" > "$tmp"
  mv "$tmp" "$path"
}

ensure_directories() {
  mkdir -p "$DATA_DIR"/cluster "$DATA_DIR"/users "$DATA_DIR"/infra "$DATA_DIR"/domains "$DATA_DIR"/dns/zones "$DATA_DIR"/openresty
}

check_ports() {
  local ips_csv="$1"
  local ports_csv="$2"
  local missing_tools=0
  if ! command -v ss >/dev/null 2>&1; then
    echo "Warning: ss not found, skipping port checks" >&2
    missing_tools=1
  fi
  if [[ $missing_tools -eq 1 ]]; then
    return
  fi
  IFS=',' read -r -a ips_arr <<<"$ips_csv"
  IFS=',' read -r -a ports_arr <<<"$ports_csv"
  for ip in "${ips_arr[@]}"; do
    for port in "${ports_arr[@]}"; do
      if ss -Htnul sport = :"$port" | grep -q "$ip:$port"; then
        abort "Port $port already in use on $ip"
      fi
    done
  done
}

create_admin_user() {
  local email="$1"
  local password="$2"
  local user_id="$3"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  require_command docker
  local hash
  hash="$(docker run --rm httpd:2.4-alpine htpasswd -nbB admin "$password" | cut -d: -f2)"
  local payload="[
  {
    \"id\": \"$user_id\",
    \"email\": \"$email\",
    \"role\": \"admin\",
    \"password\": \"$hash\",
    \"created_at\": \"$timestamp\",
    \"updated_at\": \"$timestamp\"
  }
]"
  write_file_atomic "$DATA_DIR/users/users.json" "$payload"
}

write_node_files() {
  python3 - "$DATA_DIR" "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import json
import sys
from pathlib import Path

data_dir, node_id, node_name, ips_csv, ns_ips_csv, ns_label, ns_base = sys.argv[1:8]

def csv_to_list(value):
    if not value:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]

node = {
    "name": node_name,
    "node_id": node_id,
    "ips": csv_to_list(ips_csv),
    "ns_ips": csv_to_list(ns_ips_csv),
    "ns_label": ns_label,
    "ns_base_domain": ns_base,
}

cluster_path = Path(data_dir) / "cluster" / "node.json"
cluster_path.write_text(json.dumps(node, indent=2))

infra_path = Path(data_dir) / "infra" / "nodes.json"
if not infra_path.exists():
    infra_path.write_text(json.dumps([{
        "id": node_id,
        "name": node_name,
        "ips": node["ips"],
        "ns_ips": node["ns_ips"],
        "ns_label": ns_label,
        "ns_base_domain": ns_base,
    }], indent=2))
PY
}

write_env_file() {
  local enable_coredns="$1"
  local enable_openresty="$2"
  cat > "$PROJECT_DIR/.env" <<EOF
BACKEND_PORT=$BACKEND_PORT
FRONTEND_PORT=$FRONTEND_PORT
FRONTEND_API_BASE=http://localhost:$BACKEND_PORT
NODE_ID=$NODE_ID
NODE_NAME=$NODE_NAME
ENABLE_COREDNS=$enable_coredns
ENABLE_OPENRESTY=$enable_openresty
SYNC_INTERVAL_SECONDS=15
RELOAD_DEBOUNCE_MS=1500
JWT_SECRET_FILE=/data/cluster/jwt_secret
CLUSTER_SECRET_FILE=/data/cluster/secret
EOF
}

render_configs() {
  (cd "$PROJECT_DIR" && docker compose run --rm --entrypoint /app/bin/generate backend \
    --data-dir /data \
    --coredns-template /app/coredns/Corefile.tmpl \
    --nginx-template /app/openresty/nginx.conf.tmpl \
    --sites-template /app/openresty/sites.tmpl \
    --openresty-output /data/openresty \
    all) || true
}

bring_up_compose() {
  (cd "$PROJECT_DIR" && docker compose up -d)
}

write_secret_files() {
  local cluster_secret="$1"
  local jwt_secret="$2"
  echo "$cluster_secret" > "$DATA_DIR/cluster/secret"
  chmod 600 "$DATA_DIR/cluster/secret"
  echo "$jwt_secret" > "$DATA_DIR/cluster/jwt_secret"
  chmod 600 "$DATA_DIR/cluster/jwt_secret"
}

pull_snapshot() {
  local seed_url="$1"
  local secret="$2"
  require_command curl
  local auth_header
  auth_header="Bearer $(python3 -c 'import binascii,sys; sys.stdout.write(binascii.hexlify(sys.stdin.buffer.read()).decode())' <<<"$secret")"
  curl -fsSL -X POST -H "Authorization: $auth_header" "$seed_url/api/v1/sync/pull" -o "$DATA_DIR/cluster/snapshot.json"
}

apply_snapshot() {
  local snapshot="$DATA_DIR/cluster/snapshot.json"
  if [[ ! -f "$snapshot" ]]; then
    abort "Snapshot file not found"
  fi
  python3 - "$snapshot" "$DATA_DIR" <<'PY'
import json
import sys
from pathlib import Path

snapshot_path = Path(sys.argv[1])
data_dir = Path(sys.argv[2])

snapshot = json.loads(snapshot_path.read_text())

domains = snapshot.get("domains", [])
for domain in domains:
    domain_dir = data_dir / "domains" / domain["domain"].lower()
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "record.json").write_text(json.dumps(domain, indent=2))

users = snapshot.get("users", [])
(data_dir / "users").mkdir(exist_ok=True)
(data_dir / "users" / "users.json").write_text(json.dumps(users, indent=2))

nodes = snapshot.get("nodes", [])
(data_dir / "infra").mkdir(exist_ok=True)
(data_dir / "infra" / "nodes.json").write_text(json.dumps(nodes, indent=2))

snapshot_path.unlink(missing_ok=True)
PY
}

main() {
  parse_args "$@"

  maybe_bootstrap

  require_command python3
  require_command openssl


  if [[ -z "$MODE" ]]; then
    echo "Installation mode not provided, entering interactive setup"
    select choice in "Fresh install" "Join cluster"; do
      case $REPLY in
        1) MODE="fresh"; break ;;
        2) MODE="join"; break ;;
        *) echo "Invalid choice" ;;
      esac
    done
  fi

  if [[ "$MODE" != "fresh" && "$MODE" != "join" ]]; then
    abort "Mode must be 'fresh' or 'join'"
  fi

  prompt_if_empty NODE_NAME "Node name"
  prompt_if_empty IPS "All node IPs (comma separated)"
  IPS="$(normalize_csv "$IPS")"
  prompt_if_empty NS_IPS "Nameserver IPs (comma separated, leave blank if none)"
  NS_IPS="$(normalize_csv "$NS_IPS")"
  prompt_if_empty NS_LABEL "NS label"
  prompt_if_empty NS_BASE_DOMAIN "NS base domain"
  prompt_if_empty BACKEND_PORT "Backend port"
  prompt_if_empty FRONTEND_PORT "Frontend port"

  if [[ -z "$NS_LABEL" ]]; then
    NS_LABEL="dns"
  fi

  if [[ -z "$NODE_ID" ]]; then
    NODE_ID="$(generate_uuid)"
  fi

  ensure_directories

  if [[ "$MODE" == "fresh" ]]; then
    prompt_if_empty ADMIN_EMAIL "Initial admin email"
    if [[ -z "$ADMIN_PASS" && -n "$ADMIN_PASS_FILE" && -f "$ADMIN_PASS_FILE" ]]; then
      ADMIN_PASS="$(<"$ADMIN_PASS_FILE")"
    fi
    prompt_secret_if_empty ADMIN_PASS "Initial admin password"

    local cluster_secret jwt_secret
    cluster_secret="$(generate_secret)"
    jwt_secret="$(generate_secret)"
    write_secret_files "$cluster_secret" "$jwt_secret"

    local admin_id
    admin_id="$(generate_uuid)"
    create_admin_user "$ADMIN_EMAIL" "$ADMIN_PASS" "$admin_id"

    write_node_files "$NODE_ID" "$NODE_NAME" "$IPS" "$NS_IPS" "$NS_LABEL" "$NS_BASE_DOMAIN"

    echo '{"peers":[]}' > "$DATA_DIR/cluster/peers.json"

    local enable_dns enable_proxy
    enable_dns="false"
    if [[ -n "$NS_IPS" ]]; then
      enable_dns="true"
    fi
    if [[ "$ENABLE_COREDNS" == "true" || "$ENABLE_COREDNS" == "false" ]]; then
      enable_dns="$ENABLE_COREDNS"
    fi

    enable_proxy="true"
    if [[ "$ENABLE_OPENRESTY" == "true" || "$ENABLE_OPENRESTY" == "false" ]]; then
      enable_proxy="$ENABLE_OPENRESTY"
    fi

    write_env_file "$enable_dns" "$enable_proxy"
  else
    if [[ -z "$SEED" ]]; then
      prompt_if_empty SEED "Seed backend URL (e.g. http://1.2.3.4:8080)"
    fi
    if [[ -z "$SECRETS_SUPPLIED" ]]; then
      prompt_secret_if_empty SECRETS_SUPPLIED "Cluster secret"
    fi
    if [[ -z "$JWT_SECRET_INPUT" ]]; then
      prompt_secret_if_empty JWT_SECRET_INPUT "JWT secret"
    fi
    write_secret_files "$SECRETS_SUPPLIED" "$JWT_SECRET_INPUT"
    write_node_files "$NODE_ID" "$NODE_NAME" "$IPS" "$NS_IPS" "$NS_LABEL" "$NS_BASE_DOMAIN"
    pull_snapshot "$SEED" "$SECRETS_SUPPLIED"
    apply_snapshot
    # Determine service flags based on roles
    local enable_dns="false"
    if [[ -n "$NS_IPS" ]]; then
      enable_dns="true"
    fi
    local enable_proxy="true"
    if [[ "$ENABLE_COREDNS" == "true" || "$ENABLE_COREDNS" == "false" ]]; then
      enable_dns="$ENABLE_COREDNS"
    fi
    if [[ "$ENABLE_OPENRESTY" == "true" || "$ENABLE_OPENRESTY" == "false" ]]; then
      enable_proxy="$ENABLE_OPENRESTY"
    fi
    write_env_file "$enable_dns" "$enable_proxy"
  fi

  check_ports "$NS_IPS" "53" || true
  check_ports "$IPS" "80,443" || true

  render_configs
  bring_up_compose

  echo "Installation completed."
  echo "Backend API: http://localhost:$BACKEND_PORT"
  echo "Frontend UI: http://localhost:$FRONTEND_PORT"
}

main "$@"
