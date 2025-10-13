#!/usr/bin/env bash
set -euo pipefail

AUTO_FIREWALL="${AUTO_FIREWALL:-auto}"
if [[ "${AUTO_FIREWALL,,}" == "false" ]]; then
  exit 0
fi

DATA_DIR="${DATA_DIR:-/data}"
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
ENV_FILE="${ENV_FILE:-${PROJECT_DIR}/.env}"
NODE_FILE="${DATA_DIR}/cluster/node.json"
INFRA_FILE="${DATA_DIR}/infra/nodes.json"
PYTHON_BIN="$(command -v python3 || command -v python || true)"

if [[ -z "$PYTHON_BIN" ]]; then
  # No interpreter available (e.g. inside the backend container); skip.
  exit 0
fi

if [[ ! -f "$NODE_FILE" || ! -f "$INFRA_FILE" ]]; then
  exit 0
fi

readarray -t CONFIG <<<"$("$PYTHON_BIN" - <<'PY'
import json
import os

data_dir = os.environ.get("DATA_DIR", "/data")
node_path = os.path.join(data_dir, "cluster", "node.json")
infra_path = os.path.join(data_dir, "infra", "nodes.json")

with open(node_path, "r", encoding="utf-8") as fh:
    node_info = json.load(fh)
node_id = node_info.get("node_id")

with open(infra_path, "r", encoding="utf-8") as fh:
    nodes = json.load(fh) or []

target = None
for candidate in nodes:
    if candidate.get("id") == node_id:
        target = candidate
        break

# Fall back to local snapshot if orchestration hasn't pushed cluster state yet.
if target is None:
    target = {
        "edge_ips": node_info.get("edge_ips", []),
        "ns_ips": node_info.get("ns_ips", []),
    }

edge_ips = list(filter(None, (target or {}).get("edge_ips", [])))
ns_ips = list(filter(None, (target or {}).get("ns_ips", [])))

tcp_ports = {int(os.environ.get("BACKEND_PORT", "8080"))}
udp_ports = set()

if edge_ips:
    tcp_ports.update({80, 443})
if ns_ips:
    tcp_ports.add(53)
    udp_ports.add(53)

print(",".join(str(p) for p in sorted(tcp_ports)))
print(",".join(str(p) for p in sorted(udp_ports)))
print("true" if ns_ips else "false")
print("true" if edge_ips else "false")
PY
)"

TCP_PORTS="${CONFIG[0]}"
UDP_PORTS="${CONFIG[1]}"
DNS_FLAG="${CONFIG[2]:-false}"
PROXY_FLAG="${CONFIG[3]:-false}"
export DATA_DIR PROJECT_DIR ENV_FILE DNS_FLAG PROXY_FLAG

EDGE_CONN_LIMIT="${EDGE_CONN_LIMIT:-${EDGE_LIMIT_CONN_PER_IP:-200}}"
EDGE_CONN_RATE="${EDGE_CONN_RATE:-${EDGE_LIMIT_REQ_PER_IP:-200}}"
EDGE_CONN_BURST="${EDGE_CONN_BURST:-${EDGE_LIMIT_REQ_BURST:-400}}"
DNS_RATE_LIMIT="${DNS_RATE_LIMIT:-800}"
DNS_RATE_BURST="${DNS_RATE_BURST:-1600}"
DNS_TCP_RATE_LIMIT="${DNS_TCP_RATE_LIMIT:-120}"
DNS_TCP_BURST="${DNS_TCP_BURST:-240}"

ensure_iptables_rule() {
  local proto="$1"
  local port="$2"
  if ! command -v iptables >/dev/null 2>&1; then
    return 1
  fi
  if iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1; then
    return 0
  fi
  iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1
}

ensure_nf_tables_rule() {
  local proto="$1"
  local port="$2"
  if ! command -v nft >/dev/null 2>&1; then
    return 1
  fi
  if nft list ruleset | grep -q "dport $port"; then
    return 0
  fi
  nft add rule inet filter input $proto dport "$port" accept >/dev/null 2>&1 || true
}

ensure_ufw_rule() {
  local proto="$1"
  local port="$2"
  if ! command -v ufw >/dev/null 2>&1; then
    return 1
  fi
  if ! ufw status | grep -q "Status: active"; then
    return 1
  fi
  ufw --force allow "$port"/"$proto" >/dev/null 2>&1 || true
}

open_port() {
  local proto="$1"
  local port_list="$2"
  if [[ -z "$port_list" ]]; then
    return
  fi
  IFS=',' read -ra ports <<<"$port_list"
  for port in "${ports[@]}"; do
    [[ -z "$port" ]] && continue
    ensure_iptables_rule "$proto" "$port" >/dev/null 2>&1 || true
    ensure_nf_tables_rule "$proto" "$port" >/dev/null 2>&1 || true
    ensure_ufw_rule "$proto" "$port" >/dev/null 2>&1 || true
  done
}

open_port tcp "$TCP_PORTS"
open_port udp "$UDP_PORTS"

iptables_available() {
  command -v iptables >/dev/null 2>&1
}

setup_edge_guard_chain() {
  iptables_available || return
  (
    set +e
    iptables -N AKI_EDGE_GUARD >/dev/null 2>&1
    iptables -F AKI_EDGE_GUARD >/dev/null 2>&1
    iptables -A AKI_EDGE_GUARD -m conntrack --ctstate INVALID -j DROP >/dev/null 2>&1
    iptables -A AKI_EDGE_GUARD -p tcp -m conntrack --ctstate NEW \
      -m hashlimit --hashlimit-name aki-edge-new --hashlimit-mode srcip \
      --hashlimit-above "${EDGE_CONN_RATE}/second" \
      --hashlimit-burst "${EDGE_CONN_BURST}" \
      --hashlimit-htable-size 32768 \
      --hashlimit-htable-expire 10000 -j DROP >/dev/null 2>&1 || true
    iptables -A AKI_EDGE_GUARD -p tcp -m connlimit \
      --connlimit-mask 32 \
      --connlimit-above "$EDGE_CONN_LIMIT" -j DROP >/dev/null 2>&1 || true
    iptables -A AKI_EDGE_GUARD -j RETURN >/dev/null 2>&1
  )
}

setup_dns_guard_chain() {
  iptables_available || return
  (
    set +e
    iptables -N AKI_DNS_GUARD >/dev/null 2>&1
    iptables -F AKI_DNS_GUARD >/dev/null 2>&1
    iptables -A AKI_DNS_GUARD -m conntrack --ctstate INVALID -j DROP >/dev/null 2>&1
    iptables -A AKI_DNS_GUARD -p udp -m hashlimit \
      --hashlimit-name aki-dns-pps --hashlimit-mode srcip \
      --hashlimit-above "${DNS_RATE_LIMIT}/second" \
      --hashlimit-burst "${DNS_RATE_BURST}" \
      --hashlimit-htable-size 32768 \
      --hashlimit-htable-expire 10000 -j DROP >/dev/null 2>&1 || true
    iptables -A AKI_DNS_GUARD -p tcp -m conntrack --ctstate NEW \
      -m hashlimit --hashlimit-name aki-dns-tcp --hashlimit-mode srcip \
      --hashlimit-above "${DNS_TCP_RATE_LIMIT}/second" \
      --hashlimit-burst "${DNS_TCP_BURST}" \
      --hashlimit-htable-size 32768 \
      --hashlimit-htable-expire 10000 -j DROP >/dev/null 2>&1 || true
    iptables -A AKI_DNS_GUARD -p tcp -m connlimit \
      --connlimit-mask 32 \
      --connlimit-above "$((DNS_TCP_BURST / 2))" -j DROP >/dev/null 2>&1 || true
    iptables -A AKI_DNS_GUARD -j RETURN >/dev/null 2>&1
  )
}

attach_guard_rule() {
  local port="$1"
  local proto="$2"
  local chain="$3"
  iptables_available || return
  [[ -z "$port" ]] && return
  (
    set +e
    if ! iptables -C INPUT -p "$proto" --dport "$port" -m conntrack --ctstate NEW -j "$chain" >/dev/null 2>&1; then
      iptables -I INPUT -p "$proto" --dport "$port" -m conntrack --ctstate NEW -j "$chain" >/dev/null 2>&1
    fi
  )
}

configure_iptables_guards() {
  iptables_available || return

  local -a tcp_ports=()
  local -a udp_ports=()
  if [[ -n "$TCP_PORTS" ]]; then
    IFS=',' read -ra tcp_ports <<<"$TCP_PORTS"
  fi
  if [[ -n "$UDP_PORTS" ]]; then
    IFS=',' read -ra udp_ports <<<"$UDP_PORTS"
  fi

  local need_edge_guard=0
  for port in "${tcp_ports[@]}"; do
    port="${port//[[:space:]]/}"
    [[ -z "$port" ]] && continue
    if [[ "$port" != "53" ]]; then
      need_edge_guard=1
      break
    fi
  done
  if (( need_edge_guard )); then
    setup_edge_guard_chain
    for port in "${tcp_ports[@]}"; do
      port="${port//[[:space:]]/}"
      [[ -z "$port" ]] && continue
      if [[ "$port" == "53" ]]; then
        continue
      fi
      attach_guard_rule "$port" "tcp" "AKI_EDGE_GUARD"
    done
  fi

  local need_dns_guard=0
  if [[ "${DNS_FLAG,,}" == "true" ]]; then
    need_dns_guard=1
  else
    for port in "${udp_ports[@]}"; do
      port="${port//[[:space:]]/}"
      if [[ -n "$port" ]]; then
        need_dns_guard=1
        break
      fi
    done
    if (( ! need_dns_guard )); then
      for port in "${tcp_ports[@]}"; do
        port="${port//[[:space:]]/}"
        if [[ "$port" == "53" ]]; then
          need_dns_guard=1
          break
        fi
      done
    fi
  fi

  if (( need_dns_guard )); then
    setup_dns_guard_chain
    for port in "${udp_ports[@]}"; do
      port="${port//[[:space:]]/}"
      [[ -z "$port" ]] && continue
      attach_guard_rule "$port" "udp" "AKI_DNS_GUARD"
    done
    for port in "${tcp_ports[@]}"; do
      port="${port//[[:space:]]/}"
      [[ "$port" == "53" ]] || continue
      attach_guard_rule "$port" "tcp" "AKI_DNS_GUARD"
    done
  fi
}

configure_iptables_guards

if [[ -f "$ENV_FILE" ]]; then
  "$PYTHON_BIN" - <<'PY'
import os

env_path = os.environ["ENV_FILE"]
desired = {
    "ENABLE_COREDNS": os.environ.get("DNS_FLAG", "false"),
    "ENABLE_OPENRESTY": os.environ.get("PROXY_FLAG", "false"),
}

with open(env_path, "r", encoding="utf-8") as fh:
    lines = fh.read().splitlines()

result = []
seen = set()
for line in lines:
    if "=" not in line or line.strip().startswith("#"):
        result.append(line)
        continue
    key, _, _ = line.partition("=")
    key = key.strip()
    if key in desired:
        value = desired[key]
        result.append(f"{key}={value}")
        seen.add(key)
    else:
        result.append(line)

for key, value in desired.items():
    if key not in seen:
        result.append(f"{key}={value}")

with open(env_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(result) + "\n")
PY
fi

exit 0
