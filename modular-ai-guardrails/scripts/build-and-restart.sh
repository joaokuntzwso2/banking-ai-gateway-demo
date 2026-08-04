#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="${DEMO_HOME:-$(cd "$PACKAGE_ROOT/.." && pwd)}"
GATEWAY_HOME="${GATEWAY_HOME:-$DEMO_HOME/wso2apip-ai-gateway-1.1.0}"
CONTROLLER_ADMIN_URL="${CONTROLLER_ADMIN_URL:-http://localhost:9094/health}"
RUNTIME_ADMIN_URL="${RUNTIME_ADMIN_URL:-http://localhost:9901/ready}"
READY_ATTEMPTS="${READY_ATTEMPTS:-90}"
READY_INTERVAL_SECONDS="${READY_INTERVAL_SECONDS:-2}"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$DEMO_HOME/evidence"
cd "$GATEWAY_HOME"

set -o pipefail
ap gateway image build 2>&1 |
  tee "$DEMO_HOME/evidence/modular-policy-build-$STAMP.log"

docker compose \
  -p ai-gateway \
  --env-file configs/keys.env \
  up -d \
  --force-recreate \
  --remove-orphans \
  --pull never

printf '\nWaiting for Gateway Controller and Runtime readiness'
controller_ready=false
runtime_ready=false

for ((attempt=1; attempt<=READY_ATTEMPTS; attempt++)); do
  if [[ "$controller_ready" != true ]] &&
    curl -fsS --max-time 3 "$CONTROLLER_ADMIN_URL" \
      >/dev/null 2>&1; then
    controller_ready=true
  fi

  if [[ "$runtime_ready" != true ]] &&
    curl -fsS --max-time 3 "$RUNTIME_ADMIN_URL" \
      >/tmp/ai-gateway-runtime-ready.txt 2>/dev/null; then
    runtime_ready=true
  fi

  if [[ "$controller_ready" == true && "$runtime_ready" == true ]]; then
    printf ' ready\n'
    break
  fi

  printf '.'
  sleep "$READY_INTERVAL_SECONDS"
done

if [[ "$controller_ready" != true || "$runtime_ready" != true ]]; then
  printf '\nGateway did not become ready in time (controller=%s runtime=%s).\n' \
    "$controller_ready" "$runtime_ready" >&2

  docker compose \
    -p ai-gateway \
    --env-file configs/keys.env \
    ps -a >&2

  docker compose \
    -p ai-gateway \
    --env-file configs/keys.env \
    logs --tail=120 --no-color \
      gateway-controller gateway-runtime >&2 || true

  exit 1
fi

docker compose \
  -p ai-gateway \
  --env-file configs/keys.env \
  ps -a
