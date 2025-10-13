#!/usr/bin/env bash
set -euo pipefail

AUTO_FIREWALL="${AUTO_FIREWALL:-auto}"
if [[ "${AUTO_FIREWALL,,}" == "false" ]]; then
  exit 0
fi

PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
DATA_DIR="${DATA_DIR:-${PROJECT_DIR}/data}"
ENABLE_DNS="${ENABLE_DNS:-false}"
ENABLE_PROXY="${ENABLE_PROXY:-false}"

if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

service_path="/etc/systemd/system/aki-firewall.service"
timer_path="/etc/systemd/system/aki-firewall.timer"

require_root_tools() {
  if [[ $EUID -eq 0 ]]; then
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo not available; skipping firewall timer install" >&2
    exit 0
  fi
  if ! sudo -n true >/dev/null 2>&1; then
    echo "passwordless sudo not configured; skipping firewall timer install" >&2
    exit 0
  fi
}

write_unit_file() {
  local path="$1"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ $EUID -eq 0 ]]; then
    if ! mv "$tmp" "$path"; then
      rm -f "$tmp"
      exit 1
    fi
  else
    if ! sudo -n mv "$tmp" "$path"; then
      rm -f "$tmp"
      exit 1
    fi
  fi
  rm -f "$tmp"
}

run_systemctl() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  if [[ $EUID -eq 0 ]]; then
    systemctl "$@"
  else
    sudo -n systemctl "$@"
  fi
}

require_root_tools

write_unit_file "$service_path" <<EOF
[Unit]
Description=aki-cloud firewall synchronisation
After=network.target

[Service]
Type=oneshot
Environment=PROJECT_DIR=${PROJECT_DIR}
Environment=DATA_DIR=${DATA_DIR}
Environment=AUTO_FIREWALL=${AUTO_FIREWALL}
Environment=ENABLE_DNS=${ENABLE_DNS}
Environment=ENABLE_PROXY=${ENABLE_PROXY}
ExecStart=${PROJECT_DIR}/scripts/configure_firewall.sh
EOF

write_unit_file "$timer_path" <<'EOF'
[Unit]
Description=Run aki-cloud firewall synchronisation periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=2m
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

run_systemctl daemon-reload
run_systemctl enable --now aki-firewall.timer >/dev/null 2>&1 || true
run_systemctl start aki-firewall.service >/dev/null 2>&1 || true

exit 0
