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

cat >"$service_path" <<EOF
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

cat >"$timer_path" <<'EOF'
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

systemctl daemon-reload
systemctl enable --now aki-firewall.timer >/dev/null 2>&1 || true
systemctl start aki-firewall.service >/dev/null 2>&1 || true

exit 0
