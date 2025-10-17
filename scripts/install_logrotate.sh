#!/usr/bin/env bash
set -euo pipefail

LOGROTATE_CONFIG_PATH="${LOGROTATE_CONFIG_PATH:-/etc/logrotate.d/aki-openresty}"

run_as_root() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
    return $?
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -n "$@"
    return $?
  fi
  if command -v doas >/dev/null 2>&1; then
    doas "$@"
    return $?
  fi
  return 1
}

if ! command -v logrotate >/dev/null 2>&1; then
  exit 0
fi

CONFIG_DIR="$(dirname "$LOGROTATE_CONFIG_PATH")"
if ! run_as_root mkdir -p "$CONFIG_DIR"; then
  echo "Skipping logrotate configuration; insufficient permissions" >&2
  exit 0
fi

tmp_file="$(mktemp)"
cat >"$tmp_file" <<'CFG'
/var/log/nginx/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    sharedscripts
    create 0640 root adm
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 "$(cat /var/run/nginx.pid)" 2>/dev/null || true
        fi
    endscript
}
CFG

if ! run_as_root mv "$tmp_file" "$LOGROTATE_CONFIG_PATH"; then
  rm -f "$tmp_file"
  echo "Failed to install logrotate configuration" >&2
  exit 0
fi
run_as_root chmod 0644 "$LOGROTATE_CONFIG_PATH"

exit 0
