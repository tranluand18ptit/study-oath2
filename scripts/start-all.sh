#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done

  wait || true
}

trap cleanup INT TERM EXIT

start_service() {
  local name="$1"
  local workdir="$2"
  local command="$3"

  (
    cd "$workdir"
    echo "[$name] starting in $workdir"
    exec $command
  ) &

  PIDS+=("$!")
}

start_service "auth" "$ROOT_DIR/auth-server" "npm start"
start_service "resource" "$ROOT_DIR/resource-server" "npm start"
start_service "frontend" "$ROOT_DIR/frontend" "npm start"

wait