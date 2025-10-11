#!/usr/bin/env bash
set -euo pipefail

AUTO_FIREWALL="${AUTO_FIREWALL:-auto}"
if [[ "${AUTO_FIREWALL,,}" == "false" ]]; then
  exit 0
fi

DATA_DIR="${DATA_DIR:-/data}"
NODE_FILE="${DATA_DIR}/cluster/node.json"
INFRA_FILE="${DATA_DIR}/infra/nodes.json"

if [[ ! -f "$NODE_FILE" || ! -f "$INFRA_FILE" ]]; then
  exit 0
fi

readarray -t CONFIG <<<"$(python3 - <<'PY'
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
PY
)"

TCP_PORTS="${CONFIG[0]}"
UDP_PORTS="${CONFIG[1]}"

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

exit 0
