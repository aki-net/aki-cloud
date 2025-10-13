#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${SYSCTL_CONFIG_PATH:-/etc/sysctl.d/90-aki-cloud.conf}"
LIMITS_PATH="${LIMITS_CONFIG_PATH:-/etc/security/limits.d/90-aki-cloud.conf}"
SYSTEM_USER="${SYSTEM_USER:-akicloud}"
NOFILE_LIMIT="${AKI_NOFILE_LIMIT:-262144}"

SYSCTL_PARAMS=(
  "fs.file-max:::1048576"
  "fs.inotify.max_user_watches:::1048576"
  "fs.inotify.max_user_instances:::1024"
  "net.core.netdev_max_backlog:::16384"
  "net.core.optmem_max:::65535"
  "net.core.rmem_max:::16777216"
  "net.core.somaxconn:::8192"
  "net.core.wmem_max:::16777216"
  "net.ipv4.conf.all.accept_redirects:::0"
  "net.ipv4.conf.all.accept_source_route:::0"
  "net.ipv4.conf.all.log_martians:::1"
  "net.ipv4.conf.all.rp_filter:::1"
  "net.ipv4.conf.all.send_redirects:::0"
  "net.ipv4.conf.default.accept_redirects:::0"
  "net.ipv4.conf.default.accept_source_route:::0"
  "net.ipv4.conf.default.log_martians:::1"
  "net.ipv4.conf.default.rp_filter:::1"
  "net.ipv4.conf.default.send_redirects:::0"
  "net.ipv4.icmp_echo_ignore_broadcasts:::1"
  "net.ipv4.icmp_ignore_bogus_error_responses:::1"
  "net.ipv4.ip_local_port_range:::10240 65535"
  "net.ipv4.tcp_fin_timeout:::15"
  "net.ipv4.tcp_keepalive_time:::600"
  "net.ipv4.tcp_max_syn_backlog:::16384"
  "net.ipv4.tcp_max_tw_buckets:::2000000"
  "net.ipv4.tcp_rmem:::4096 131072 4186112"
  "net.ipv4.tcp_syncookies:::1"
  "net.ipv4.tcp_synack_retries:::3"
  "net.ipv4.tcp_timestamps:::1"
  "net.ipv4.tcp_tw_reuse:::1"
  "net.ipv4.tcp_wmem:::4096 65536 4186112"
  "net.ipv4.neigh.default.gc_thresh1:::4096"
  "net.ipv4.neigh.default.gc_thresh2:::8192"
  "net.ipv4.neigh.default.gc_thresh3:::16384"
  "net.netfilter.nf_conntrack_buckets:::32768"
  "net.netfilter.nf_conntrack_max:::262144"
  "net.netfilter.nf_conntrack_tcp_timeout_close_wait:::60"
  "net.netfilter.nf_conntrack_tcp_timeout_established:::432000"
)

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

ensure_root_available() {
  if run_as_root true >/dev/null 2>&1; then
    return 0
  fi
  cat >&2 <<'EOF'
WARNING: Unable to obtain root privileges; kernel/network tuning was skipped.
Run scripts/apply_sysctl.sh manually as root to apply baseline hardening.
EOF
  return 1
}

build_sysctl_content() {
  printf '# Managed by aki-cloud installer – baseline kernel/network hardening\n'
  printf '# Re-run scripts/apply_sysctl.sh to refresh.\n'
  for entry in "${SYSCTL_PARAMS[@]}"; do
    IFS=':::' read -r key value <<<"$entry"
    local sysctl_path="/proc/sys/${key//./\/}"
    if [[ -e "$sysctl_path" ]]; then
      printf '%s = %s\n' "$key" "$value"
    fi
  done
}

apply_sysctl_runtime() {
  for entry in "${SYSCTL_PARAMS[@]}"; do
    IFS=':::' read -r key value <<<"$entry"
    local sysctl_path="/proc/sys/${key//./\/}"
    if [[ -e "$sysctl_path" ]]; then
      run_as_root sysctl -q -w "${key}=${value}" >/dev/null 2>&1 || true
    fi
  done
}

write_file_as_root() {
  local path="$1"
  local content="$2"
  local dir
  dir="$(dirname "$path")"
  run_as_root mkdir -p "$dir"
  local tmp
  tmp="$(mktemp)"
  printf '%s\n' "$content" >"$tmp"
  run_as_root mv "$tmp" "$path"
  run_as_root chmod 0644 "$path"
}

build_limits_content() {
  cat <<EOF
# Managed by aki-cloud installer – relaxed file descriptor limits
* soft nofile ${NOFILE_LIMIT}
* hard nofile ${NOFILE_LIMIT}
EOF
  if [[ -n "${SYSTEM_USER:-}" ]]; then
    cat <<EOF
${SYSTEM_USER} soft nofile ${NOFILE_LIMIT}
${SYSTEM_USER} hard nofile ${NOFILE_LIMIT}
EOF
  fi
}

main() {
  if ! ensure_root_available; then
    exit 0
  fi

  sysctl_content="$(build_sysctl_content)"
  write_file_as_root "$CONFIG_PATH" "$sysctl_content"
  apply_sysctl_runtime
  run_as_root sysctl -q -p "$CONFIG_PATH" >/dev/null 2>&1 || true

  limits_content="$(build_limits_content)"
  write_file_as_root "$LIMITS_PATH" "$limits_content"
}

main "$@"
