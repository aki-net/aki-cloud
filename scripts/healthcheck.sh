#!/usr/bin/env bash
set -euo pipefail

PORT="${BACKEND_PORT:-8080}"
curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null
curl -fsS "http://127.0.0.1:${PORT}/readyz" >/dev/null
echo "backend healthy"
