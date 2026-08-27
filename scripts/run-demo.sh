#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONSOLE_DIR="$ROOT_DIR/bank-ai-security-console"
MODULAR_DIR="$ROOT_DIR/modular-ai-guardrails"
GATEWAY_HOME="$ROOT_DIR/wso2apip-ai-gateway-1.1.0"
ENV_FILE="$CONSOLE_DIR/.env"
CHAIN_FILE="$MODULAR_DIR/config/modular-policy-chain.json"
KEY_FILE="$GATEWAY_HOME/configs/customer-ai-secure-modular-key-latest.json"
WORKSPACE_SECRETS_FILE="$GATEWAY_HOME/configs/workspace-secrets.env"

CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:9090}"
CONTROLLER_HEALTH_URL="${CONTROLLER_HEALTH_URL:-http://localhost:9094/health}"
RUNTIME_READY_URL="${RUNTIME_READY_URL:-http://localhost:9901/ready}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
PROXY_ID="${PROXY_ID:-customer-ai-secure}"
WORKSPACE_PROVIDER_ID="${WORKSPACE_PROVIDER_ID:-enterprise-openai}"
PROXY_HEADER="${PROXY_HEADER:-X-API-Key}"
API_KEY_ISSUER="${API_KEY_ISSUER:-api-platform-devportal}"
READY_ATTEMPTS="${READY_ATTEMPTS:-90}"
WORKSPACE_SETTLE_SECONDS="${WORKSPACE_SETTLE_SECONDS:-8}"
API_KEY_SYNC_ATTEMPTS="${API_KEY_SYNC_ATTEMPTS:-20}"
API_KEY_SYNC_RESTART_ATTEMPTS="${API_KEY_SYNC_RESTART_ATTEMPTS:-15}"
AUTO_RUN_UNIT_TESTS="${AUTO_RUN_UNIT_TESTS:-false}"
DEMO_FORCE_BUILD="${DEMO_FORCE_BUILD:-false}"
CHECK_ONLY="${CHECK_ONLY:-false}"
PROVIDER_KEY_ROTATED=false
CLEAN_CONSOLE_DEPS="${CLEAN_CONSOLE_DEPS:-false}"
NEGATIVE_RESPONSE_FILE="${TMPDIR:-/tmp}/banking-demo-negative-$$.json"
POSITIVE_RESPONSE_FILE="${TMPDIR:-/tmp}/banking-demo-positive-$$.json"
PROVIDER_RESPONSE_FILE="${TMPDIR:-/tmp}/banking-demo-provider-$$.json"

CUSTOM_CONTROLLER_IMAGE="ghcr.io/wso2/api-platform/wso2apip-ai-gateway-1.1.0-gateway-controller:1.1.0"
CUSTOM_RUNTIME_IMAGE="ghcr.io/wso2/api-platform/wso2apip-ai-gateway-1.1.0-gateway-runtime:1.1.0"

log() { printf '\n==> %s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

usage() {
  cat <<'EOF'
Usage: ./run.sh [start|check|clean|fresh|help]

Commands:
  start   Daily/self-healing startup (default): gateway, Workspace repair, smoke tests, UI/BFF
  check   Run the same recovery and validation without starting the UI/BFF
  clean   Remove only local AI Gateway runtime state and generated demo artifacts
  fresh   Run clean, then perform a complete self-healing startup
  help    Show this help

Useful environment variables:
  DEMO_FORCE_BUILD=true     Rebuild the custom Gateway images before starting
  AUTO_RUN_UNIT_TESTS=true  Run the console unit tests during startup
  CLEAN_CONSOLE_DEPS=true   Also remove bank-ai-security-console/node_modules during clean
  API_KEY_ISSUER=value      Override the API-key issuer (default: api-platform-devportal)

For a connected Workspace first run, keep configs/keys.env with the gateway registration
host/token and deploy enterprise-openai + customer-ai-secure in AI Workspace. The runner
creates correctly issued local provider/proxy keys, repairs the 19-policy chain, configures
the console .env, waits for xDS, and validates 422/200 before starting the UI.

The clean/fresh commands preserve AI Workspace cloud resources, gateway registration
configuration, bank-ai-security-console/.env, and the locally saved provider access key.
EOF
}

file_env_value() {
  local file="$1" name="$2"
  python3 - "$file" "$name" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1]); wanted = sys.argv[2]
if not p.exists():
    raise SystemExit(0)
for line in p.read_text().splitlines():
    s=line.strip()
    if not s or s.startswith('#') or '=' not in s:
        continue
    k,v=s.split('=',1)
    if k.strip()!=wanted:
        continue
    v=v.strip()
    if len(v)>=2 and v[0]==v[-1] and v[0] in {'"', "'"}:
        v=v[1:-1]
    print(v,end='')
    break
PY
}

set_env_values() {
  python3 - "$ENV_FILE" "$@" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
pairs = {}
for item in sys.argv[2:]:
    name, value = item.split("=", 1)
    pairs[name] = value
lines = path.read_text().splitlines() if path.exists() else []
out = []
for line in lines:
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        name = stripped.split("=", 1)[0].strip()
        if name in pairs:
            continue
    out.append(line)
while out and not out[-1].strip():
    out.pop()
out.extend(["", "# Managed by scripts/run-demo.sh"])
for name, value in pairs.items():
    out.append(f"{name}={value}")
path.write_text("\n".join(out) + "\n")
PY
  chmod 600 "$ENV_FILE"
}

configure_workspace_console_defaults() {
  set_env_values \
    "DEMO_MODE=workspace" \
    "WSO2_GATEWAY_URL=https://localhost:8443/$PROXY_ID/v1/chat/completions" \
    "WSO2_API_KEY_HEADER=$PROXY_HEADER" \
    "WSO2_API_KEY_PREFIX=" \
    "WSO2_DEFAULT_MODEL=gpt-4o-mini" \
    "WSO2_ALLOW_SELF_SIGNED=true"
  ok "Configured bank-ai-security-console/.env for the connected Workspace proxy"
}

workspace_registration_present() {
  local host token
  host="$(file_env_value "$GATEWAY_HOME/configs/keys.env" GATEWAY_CONTROLPLANE_HOST || true)"
  token="$(file_env_value "$GATEWAY_HOME/configs/keys.env" GATEWAY_REGISTRATION_TOKEN || true)"
  [[ -n "$host" && -n "$token" ]]
}

save_workspace_provider_key() {
  local key="$1"
  umask 077
  mkdir -p "$(dirname "$WORKSPACE_SECRETS_FILE")"
  python3 - "$WORKSPACE_SECRETS_FILE" "$key" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); key=sys.argv[2]
lines=p.read_text().splitlines() if p.exists() else []
out=[]; updated=False
for line in lines:
    if line.startswith('WORKSPACE_PROVIDER_ACCESS_KEY='):
        out.append('WORKSPACE_PROVIDER_ACCESS_KEY='+key); updated=True
    else:
        out.append(line)
if not updated:
    if out and out[-1].strip(): out.append('')
    out.append('# Local secret used by scripts/run-demo.sh; never commit this file.')
    out.append('WORKSPACE_PROVIDER_ACCESS_KEY='+key)
p.write_text('\n'.join(out)+'\n')
PY
  chmod 600 "$WORKSPACE_SECRETS_FILE"
}

load_or_prompt_provider_key() {
  local key="${WORKSPACE_PROVIDER_ACCESS_KEY:-}"
  if [[ -z "$key" ]]; then
    key="$(file_env_value "$WORKSPACE_SECRETS_FILE" WORKSPACE_PROVIDER_ACCESS_KEY || true)"
  fi
  [[ -n "$key" ]] || die "Provider access key is not initialized. This is an internal startup error."
  printf '%s' "$key"
}

generate_provider_access_key() {
  local stamp request response key
  stamp="$(date +%Y%m%d%H%M%S)"
  request="$(mktemp)"
  response="$(mktemp)"
  umask 077

  jq -n \
    --arg name "auto-provider-$stamp" \
    --arg issuer "$API_KEY_ISSUER" \
    '{name:$name, issuer:$issuer}' > "$request"

  curl --fail-with-body -sS \
    --max-time 10 \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -X POST "$CONTROLLER_URL/api/management/v0.9/llm-providers/$WORKSPACE_PROVIDER_ID/api-keys" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary "@$request" > "$response"

  key="$(jq -er --arg provider "$WORKSPACE_PROVIDER_ID" '
    select(
      .status == "success"
      and .apiKey.status == "active"
      and .apiKey.apiId == $provider
      and (.apiKey.apiKey | type == "string" and length > 16)
    )
    | .apiKey.apiKey
  ' "$response")" || {
    cat "$response" >&2 || true
    rm -f "$request" "$response"
    die "Gateway did not return a usable provider API key."
  }

  rm -f "$request" "$response"
  WORKSPACE_PROVIDER_ACCESS_KEY="$key"
  save_workspace_provider_key "$key"
  PROVIDER_KEY_ROTATED=true
  ok "Created a local provider access key with issuer '$API_KEY_ISSUER'"
}

provider_response_is_expected() {
  jq -e '.choices[0].message.content == "PROVIDER_OK"' "$PROVIDER_RESPONSE_FILE" >/dev/null 2>&1
}

wait_for_provider_key_runtime_sync() {
  local key="$1" attempts="$2" label="${3:-provider API key}" status
  printf 'Waiting for %s to reach Gateway Runtime' "$label"
  for ((i=1; i<=attempts; i++)); do
    status="$(provider_direct_probe "$key")"
    case "$status" in
      200)
        if provider_response_is_expected; then
          printf ' ready\n'
          rm -f "$PROVIDER_RESPONSE_FILE"
          return 0
        fi
        printf ' unexpected-response\n'
        return 3
        ;;
      401|403)
        if is_gateway_key_rejection "$PROVIDER_RESPONSE_FILE"; then
          printf '.'
          rm -f "$PROVIDER_RESPONSE_FILE"
          sleep 2
        else
          printf ' upstream-auth-failed\n'
          return 2
        fi
        ;;
      *)
        printf ' HTTP %s\n' "${status:-000}"
        return 3
        ;;
    esac
  done
  printf ' timed out\n'
  return 1
}

ensure_provider_access_key() {
  local key="${WORKSPACE_PROVIDER_ACCESS_KEY:-}" status sync_rc
  if [[ -z "$key" ]]; then
    key="$(file_env_value "$WORKSPACE_SECRETS_FILE" WORKSPACE_PROVIDER_ACCESS_KEY || true)"
  fi

  if [[ -n "$key" ]]; then
    status="$(provider_direct_probe "$key")"
    if [[ "$status" == "200" ]] && provider_response_is_expected; then
      rm -f "$PROVIDER_RESPONSE_FILE"
      WORKSPACE_PROVIDER_ACCESS_KEY="$key"
      save_workspace_provider_key "$key"
      ok "Saved provider access key is valid"
      return 0
    fi

    if [[ "$status" == "401" || "$status" == "403" ]] && is_gateway_key_rejection "$PROVIDER_RESPONSE_FILE"; then
      warn "Saved provider access key is stale/invalid; creating a correctly issued local key."
      rm -f "$PROVIDER_RESPONSE_FILE"
      rm -f "$WORKSPACE_SECRETS_FILE"
      WORKSPACE_PROVIDER_ACCESS_KEY=""
    else
      warn "Direct provider smoke test returned HTTP ${status:-000}."
      cat "$PROVIDER_RESPONSE_FILE" >&2 || true
      rm -f "$PROVIDER_RESPONSE_FILE"
      if [[ "$status" == "401" || "$status" == "403" ]]; then
        die "enterprise-openai accepted the gateway API key but the upstream OpenAI credential was rejected. Update the OpenAI credential in AI Workspace."
      fi
      die "enterprise-openai is not healthy; refusing to rotate keys blindly."
    fi
  else
    warn "No usable provider access key is saved locally; creating one automatically."
  fi

  generate_provider_access_key
  key="$WORKSPACE_PROVIDER_ACCESS_KEY"

  if wait_for_provider_key_runtime_sync "$key" "$API_KEY_SYNC_ATTEMPTS" "new provider API key"; then
    ok "Provider access key is active"
    return 0
  fi
  sync_rc=$?

  if [[ "$sync_rc" == "1" ]]; then
    restart_runtime_for_xds_resync
    if wait_for_provider_key_runtime_sync "$key" "$API_KEY_SYNC_RESTART_ATTEMPTS" "new provider API key after runtime resync"; then
      ok "Provider access key is active after Runtime xDS resync"
      return 0
    fi
    sync_rc=$?
  fi

  if [[ "$sync_rc" == "2" ]]; then
    cat "$PROVIDER_RESPONSE_FILE" >&2 || true
    rm -f "$PROVIDER_RESPONSE_FILE"
    die "The Gateway accepted the provider key, but OpenAI rejected the configured upstream credential. Update enterprise-openai in AI Workspace."
  fi

  cat "$PROVIDER_RESPONSE_FILE" >&2 || true
  rm -f "$PROVIDER_RESPONSE_FILE"
  die "Provider API key did not become usable in the Gateway Runtime."
}

ensure_docker() {
  require docker
  if docker info >/dev/null 2>&1; then
    ok "Docker daemon is running"
    return
  fi
  if command -v colima >/dev/null 2>&1; then
    log "Starting Colima"
    colima start
    for ((i=1; i<=60; i++)); do
      if docker info >/dev/null 2>&1; then
        ok "Colima/Docker is ready"
        return
      fi
      sleep 2
    done
    die "Docker did not become ready after starting Colima."
  fi
  die "Docker daemon is unavailable. Start Docker Desktop/Colima and retry."
}

wait_for_url() {
  local label="$1" url="$2"
  printf 'Waiting for %s' "$label"
  for ((i=1; i<=READY_ATTEMPTS; i++)); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      printf ' ready\n'
      return 0
    fi
    printf '.'
    sleep 2
  done
  printf '\n'
  return 1
}

start_gateway() {
  log "Initializing local files"
  "$ROOT_DIR/scripts/demo.sh" init >/dev/null

  local need_build=false
  if [[ "$DEMO_FORCE_BUILD" == "true" ]]; then
    need_build=true
  elif ! docker image inspect "$CUSTOM_CONTROLLER_IMAGE" >/dev/null 2>&1 \
    || ! docker image inspect "$CUSTOM_RUNTIME_IMAGE" >/dev/null 2>&1; then
    need_build=true
  fi

  if [[ "$need_build" == "true" ]]; then
    log "Custom gateway images are missing or rebuild was requested"
    "$ROOT_DIR/scripts/demo.sh" build
  else
    log "Starting existing custom AI Gateway images"
    (
      cd "$GATEWAY_HOME"
      docker compose \
        -p ai-gateway \
        --env-file configs/keys.env \
        up -d \
        --remove-orphans \
        --pull never
    )
  fi

  wait_for_url "Gateway Controller" "$CONTROLLER_HEALTH_URL" || gateway_diagnostics
  wait_for_url "Gateway Runtime" "$RUNTIME_READY_URL" || gateway_diagnostics
  ok "Gateway Controller and Runtime are healthy"
}

gateway_diagnostics() {
  warn "Gateway failed to become healthy. Recent container state/logs follow."
  (
    cd "$GATEWAY_HOME"
    docker compose -p ai-gateway --env-file configs/keys.env ps -a >&2 || true
    docker compose -p ai-gateway --env-file configs/keys.env \
      logs --tail=120 --no-color gateway-controller gateway-runtime >&2 || true
  )
  exit 1
}

controller_get() {
  local path="$1"
  curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -H 'Accept: application/json' "$CONTROLLER_URL$path"
}

wait_for_workspace_resources() {
  printf 'Waiting for Workspace provider/proxy sync'
  for ((i=1; i<=READY_ATTEMPTS; i++)); do
    if controller_get "/api/management/v0.9/llm-providers/$WORKSPACE_PROVIDER_ID" >/dev/null 2>&1 \
      && controller_get "/api/management/v0.9/llm-proxies/$PROXY_ID" >/dev/null 2>&1; then
      printf ' ready\n'
      if [[ "$WORKSPACE_SETTLE_SECONDS" -gt 0 ]]; then
        printf 'Allowing control-plane sync to settle for %ss...\n' "$WORKSPACE_SETTLE_SECONDS"
        sleep "$WORKSPACE_SETTLE_SECONDS"
      fi
      return 0
    fi
    printf '.'
    sleep 2
  done
  printf '\n'
  die "Workspace provider/proxy did not appear in the local controller. Check gateway registration/control-plane connectivity."
}

expected_workspace_policy_names() {
  jq -c '["api-key-auth"] + (map(.name)) + ["request-rewrite"]' "$CHAIN_FILE"
}

workspace_chain_is_correct() {
  local current="$1" expected
  expected="$(expected_workspace_policy_names)"
  jq -e --argjson expected "$expected" '
    ([.spec.policies[]?.name] == $expected)
    and (
      [.spec.policies[1:-1][]?.paths[]?.path] |
      length > 0 and all(. == "/v1/chat/completions")
    )
    and (.spec.policies[-1].paths[0].params.pathRewrite.replaceFullPath == "/chat/completions")
  ' "$current" >/dev/null
}

repair_workspace_proxy() {
  local provider_key="$1"
  local current effective updated applied delegation expected_count
  current="$(mktemp)"; effective="$(mktemp)"; updated="$(mktemp)"; applied="$(mktemp)"

  delegation="$(file_env_value "$ENV_FILE" DEMO_DELEGATION_CONTEXT_SECRET || true)"
  [[ ${#delegation} -ge 24 ]] || die "DEMO_DELEGATION_CONTEXT_SECRET is missing/too short in $ENV_FILE."

  jq --arg secret "$delegation" '
    map(
      .paths |= map(.path = "/v1/chat/completions")
      | if .name == "custom-agent-tool-scope-guardrail" then
          .paths |= map(.params.demoContextHmacSecret = $secret)
        else . end
    )
  ' "$CHAIN_FILE" > "$effective"
  expected_count="$(( $(jq 'length' "$effective") + 2 ))"

  for attempt in 1 2 3; do
    controller_get "/api/management/v0.9/llm-proxies/$PROXY_ID" > "$current"

    jq --slurpfile chain "$effective" \
      --arg provider "$WORKSPACE_PROVIDER_ID" \
      --arg providerKey "$provider_key" \
      --arg header "$PROXY_HEADER" '
      del(.status)
      | .spec.provider.id = $provider
      | .spec.provider.auth = {
          type: "api-key",
          header: "X-API-Key",
          value: $providerKey
        }
      | .spec.policies = (
          [
            (([.spec.policies[]? | select(.name == "api-key-auth")][0]) // {
              name: "api-key-auth",
              version: "v1",
              paths: [{path:"/*", methods:["*"], params:{in:"header", key:$header}}]
            })
            | .paths = [{path:"/*", methods:["*"], params:{in:"header", key:$header}}]
          ]
          + $chain[0]
          + [{
              name: "request-rewrite",
              version: "v1",
              paths: [{
                path: "/v1/chat/completions",
                methods: ["POST"],
                params: {
                  pathRewrite: {
                    type: "ReplaceFullPath",
                    replaceFullPath: "/chat/completions"
                  }
                }
              }]
            }]
        )
    ' "$current" > "$updated"

    curl --fail-with-body -sS \
      -u "$ADMIN_USER:$ADMIN_PASSWORD" \
      -X PUT "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json' \
      --data-binary "@$updated" > "$applied"

    sleep 3
    controller_get "/api/management/v0.9/llm-proxies/$PROXY_ID" > "$current"
    if workspace_chain_is_correct "$current"; then
      ok "Workspace proxy repaired: $expected_count policies, provider credential restored, rewrite last"
      rm -f "$current" "$effective" "$updated" "$applied"
      return 0
    fi
    warn "Workspace proxy was changed again after repair attempt $attempt; retrying."
    sleep 3
  done

  controller_get "/api/management/v0.9/llm-proxies/$PROXY_ID" > "$current" || true
  jq '{state:.status.state, provider:.spec.provider.id, policyCount:(.spec.policies|length), policies:[.spec.policies[]?.name]}' "$current" >&2 || true
  rm -f "$current" "$effective" "$updated" "$applied"
  die "Could not keep the repo-managed Workspace policy chain active. The control plane may be continuously overwriting the local proxy."
}

ensure_workspace_chain() {
  local current provider_key
  current="$(mktemp)"
  controller_get "/api/management/v0.9/llm-proxies/$PROXY_ID" > "$current"
  if workspace_chain_is_correct "$current"; then
    ok "Repo-managed Workspace chain is already correct ($(jq '.spec.policies|length' "$current") policies)"
    rm -f "$current"
    return 0
  fi
  printf 'Current proxy has %s policies; repairing from the repository.\n' "$(jq '.spec.policies|length' "$current")"
  rm -f "$current"
  provider_key="$(load_or_prompt_provider_key)"
  repair_workspace_proxy "$provider_key"
}

load_proxy_key() {
  file_env_value "$ENV_FILE" WSO2_SECURE_API_KEY || true
}

negative_probe() {
  local key="$1" body status
  body="$(mktemp)"
  cat > "$body" <<'JSON'
{
  "model": "gpt-4o-mini",
  "temperature": 0,
  "messages": [{
    "role": "user",
    "content": "Resume la situación del empleado EMP-1007: su hija está enferma y el empleado tiene un diagnóstico médico confidencial."
  }]
}
JSON
  status="$(curl -ksS \
    --connect-timeout 5 \
    --max-time 30 \
    -o "$NEGATIVE_RESPONSE_FILE" \
    -w '%{http_code}' \
    -X POST "https://localhost:8443/$PROXY_ID/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -H "$PROXY_HEADER: $key" \
    --data-binary "@$body" || true)"
  rm -f "$body"
  printf '%s' "$status"
}

wait_for_proxy_key_runtime_sync() {
  local key="$1" attempts="$2" label="${3:-proxy API key}" status
  printf 'Waiting for %s to reach Gateway Runtime' "$label"
  for ((i=1; i<=attempts; i++)); do
    status="$(negative_probe "$key")"
    case "$status" in
      422)
        printf ' ready\n'
        rm -f "$NEGATIVE_RESPONSE_FILE"
        return 0
        ;;
      401|403)
        printf '.'
        rm -f "$NEGATIVE_RESPONSE_FILE"
        sleep 2
        ;;
      200)
        printf ' authenticated\n'
        # The key is active, but the policy snapshot may still be converging.
        return 2
        ;;
      *)
        printf ' HTTP %s\n' "${status:-000}"
        return 3
        ;;
    esac
  done
  printf ' timed out\n'
  return 1
}

restart_runtime_for_xds_resync() {
  warn "Fresh key has not reached the Runtime yet; restarting only gateway-runtime to force a new xDS snapshot."
  (
    cd "$GATEWAY_HOME"
    docker compose \
      -p ai-gateway \
      --env-file configs/keys.env \
      restart gateway-runtime
  )
  wait_for_url "Gateway Runtime" "$RUNTIME_READY_URL" || gateway_diagnostics
  sleep 3
}

positive_probe() {
  local key="$1" body status
  body="$(mktemp)"
  cat > "$body" <<'JSON'
{
  "model": "gpt-4o-mini",
  "temperature": 0,
  "messages": [{"role":"user","content":"Reply exactly with WORKSPACE_OK"}]
}
JSON
  status="$(curl -ksS \
    --connect-timeout 5 \
    --max-time 45 \
    -o "$POSITIVE_RESPONSE_FILE" \
    -w '%{http_code}' \
    -X POST "https://localhost:8443/$PROXY_ID/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -H "$PROXY_HEADER: $key" \
    --data-binary "@$body" || true)"
  rm -f "$body"
  printf '%s' "$status"
}

provider_direct_probe() {
  local provider_key="$1" context body status
  context="$(controller_get "/api/management/v0.9/llm-providers/$WORKSPACE_PROVIDER_ID" | jq -r '.spec.context')"
  body="$(mktemp)"
  cat > "$body" <<'JSON'
{"model":"gpt-4o-mini","temperature":0,"messages":[{"role":"user","content":"Reply exactly with PROVIDER_OK"}]}
JSON
  status="$(curl -ksS \
    --connect-timeout 5 \
    --max-time 45 \
    -o "$PROVIDER_RESPONSE_FILE" \
    -w '%{http_code}' \
    -X POST "https://localhost:8443${context}/chat/completions" \
    -H 'Content-Type: application/json' \
    -H "X-API-Key: $provider_key" \
    --data-binary "@$body" || true)"
  rm -f "$body"
  printf '%s' "$status"
}

generate_or_regenerate_proxy_key() {
  local stamp request tmp delegation
  stamp="$(date +%Y%m%d%H%M%S)"
  request="$(mktemp)"
  tmp="$KEY_FILE.tmp"
  umask 077

  jq -n \
    --arg name "auto-recovery-$stamp" \
    --arg issuer "$API_KEY_ISSUER" \
    '{name:$name, issuer:$issuer}' > "$request"

  curl --fail-with-body -sS \
    --max-time 10 \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -X POST "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID/api-keys" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary "@$request" > "$tmp"

  jq -e --arg proxy "$PROXY_ID" '
    .status == "success"
    and .apiKey.status == "active"
    and .apiKey.apiId == $proxy
    and (.apiKey.apiKey | type == "string" and length > 16)
  ' "$tmp" >/dev/null || {
    cat "$tmp" >&2
    rm -f "$tmp" "$request"
    die "Gateway did not return a usable proxy API key."
  }

  mv "$tmp" "$KEY_FILE"
  rm -f "$request"
  chmod 600 "$KEY_FILE"
  ok "Created a new local proxy key with issuer '$API_KEY_ISSUER'"

  delegation="$(file_env_value "$ENV_FILE" DEMO_DELEGATION_CONTEXT_SECRET || true)"
  (
    cd "$CONSOLE_DIR"
    GATEWAY_HOME="$GATEWAY_HOME" \
    ENV_FILE="$ENV_FILE" \
    DEMO_DELEGATION_CONTEXT_SECRET="$delegation" \
      ./scripts/sync-api-key.sh >/dev/null
  )
  ok "Synchronized the working proxy key into bank-ai-security-console/.env"
}

activate_new_proxy_key() {
  local key="$1" sync_rc status

  if wait_for_proxy_key_runtime_sync "$key" "$API_KEY_SYNC_ATTEMPTS" "fresh proxy API key"; then
    ok "Fresh proxy key works and guardrails block correctly"
    return 0
  fi
  sync_rc=$?

  if [[ "$sync_rc" == "1" ]]; then
    restart_runtime_for_xds_resync
    if wait_for_proxy_key_runtime_sync "$key" "$API_KEY_SYNC_RESTART_ATTEMPTS" "fresh proxy API key after runtime resync"; then
      ok "Fresh proxy key works after Runtime xDS resync"
      return 0
    fi
    sync_rc=$?
  fi

  if [[ "$sync_rc" == "2" ]]; then
    warn "Fresh key is authenticated, but the negative scenario was not blocked yet; waiting for the policy snapshot to converge."
    for ((i=1; i<=10; i++)); do
      sleep 2
      status="$(negative_probe "$key")"
      if [[ "$status" == "422" ]]; then
        rm -f "$NEGATIVE_RESPONSE_FILE"
        ok "Fresh proxy key and guardrail policy snapshot are active"
        return 0
      fi
      rm -f "$NEGATIVE_RESPONSE_FILE"
    done
  fi

  status="$(negative_probe "$key")"
  warn "Negative probe after key synchronization returned HTTP $status"
  cat "$NEGATIVE_RESPONSE_FILE" >&2 || true
  rm -f "$NEGATIVE_RESPONSE_FILE"
  die "Fresh proxy key/policy state did not converge in the Gateway Runtime."
}

ensure_proxy_key_and_guardrails() {
  local key status provider_key
  key="$(load_proxy_key)"

  if [[ -z "$key" ]]; then
    warn "No proxy key is saved in the console environment; creating one automatically."
    generate_or_regenerate_proxy_key
    key="$(load_proxy_key)"
    activate_new_proxy_key "$key"
    return 0
  fi

  status="$(negative_probe "$key")"
  case "$status" in
    422)
      rm -f "$NEGATIVE_RESPONSE_FILE"
      ok "Negative guardrail smoke test blocked as expected (HTTP 422)"
      ;;
    401|403)
      rm -f "$NEGATIVE_RESPONSE_FILE"
      warn "Saved proxy key is stale/invalid; creating a correctly issued local key."
      generate_or_regenerate_proxy_key
      key="$(load_proxy_key)"
      activate_new_proxy_key "$key"
      ;;
    200)
      warn "Negative scenario reached the model (HTTP 200); reapplying the repo policy chain once."
      cat "$NEGATIVE_RESPONSE_FILE" >&2 || true
      rm -f "$NEGATIVE_RESPONSE_FILE"
      provider_key="$(load_or_prompt_provider_key)"
      repair_workspace_proxy "$provider_key"
      status="$(negative_probe "$key")"
      [[ "$status" == "422" ]] || {
        cat "$NEGATIVE_RESPONSE_FILE" >&2 || true
        rm -f "$NEGATIVE_RESPONSE_FILE"
        die "Guardrails are still not executing after repair."
      }
      rm -f "$NEGATIVE_RESPONSE_FILE"
      ok "Guardrail chain repaired and verified"
      ;;
    *)
      warn "Negative guardrail probe returned HTTP ${status:-000}"
      cat "$NEGATIVE_RESPONSE_FILE" >&2 || true
      rm -f "$NEGATIVE_RESPONSE_FILE"
      die "Could not validate proxy authentication/guardrails."
      ;;
  esac
}

is_gateway_key_rejection() {
  local file="$1"
  jq -e '
    (.message? == "Valid API key required")
    or (.error? == "Unauthorized" and (.message? // "") == "Valid API key required")
  ' "$file" >/dev/null 2>&1
}

validate_positive_path() {
  local key status provider_key pstatus
  key="$(load_proxy_key)"
  status="$(positive_probe "$key")"
  if [[ "$status" == "200" ]]; then
    rm -f "$POSITIVE_RESPONSE_FILE"
    ok "Positive end-to-end OpenAI smoke test passed (HTTP 200)"
    return 0
  fi

  warn "Positive proxy smoke test returned HTTP ${status:-000}."
  cat "$POSITIVE_RESPONSE_FILE" >&2 || true
  rm -f "$POSITIVE_RESPONSE_FILE"

  # At this point the negative 422 probe has already proven proxy authentication.
  # A 401/403/404 here therefore points to the proxy -> provider hop/binding.
  if [[ "$status" == "401" || "$status" == "403" || "$status" == "404" ]]; then
    provider_key="$(load_or_prompt_provider_key)"
    pstatus="$(provider_direct_probe "$provider_key")"

    if [[ "$pstatus" == "200" ]] && provider_response_is_expected; then
      rm -f "$PROVIDER_RESPONSE_FILE"
      repair_workspace_proxy "$provider_key"
      status="$(positive_probe "$key")"
      if [[ "$status" == "200" ]]; then
        rm -f "$POSITIVE_RESPONSE_FILE"
        ok "Positive path recovered after restoring proxy -> provider auth/rewrite"
        return 0
      fi
      cat "$POSITIVE_RESPONSE_FILE" >&2 || true
      rm -f "$POSITIVE_RESPONSE_FILE"
    else
      warn "Direct provider smoke test returned HTTP ${pstatus:-000}."
      cat "$PROVIDER_RESPONSE_FILE" >&2 || true
      if [[ "$pstatus" == "401" || "$pstatus" == "403" ]] && is_gateway_key_rejection "$PROVIDER_RESPONSE_FILE"; then
        rm -f "$PROVIDER_RESPONSE_FILE"
        warn "Provider key unexpectedly became invalid; rotating it and rebinding the proxy."
        rm -f "$WORKSPACE_SECRETS_FILE"
        WORKSPACE_PROVIDER_ACCESS_KEY=""
        ensure_provider_access_key
        provider_key="$(load_or_prompt_provider_key)"
        repair_workspace_proxy "$provider_key"
        status="$(positive_probe "$key")"
        if [[ "$status" == "200" ]]; then
          rm -f "$POSITIVE_RESPONSE_FILE"
          ok "Positive path recovered after provider-key rotation"
          return 0
        fi
      else
        rm -f "$PROVIDER_RESPONSE_FILE"
      fi
    fi
  fi

  die "Positive end-to-end proxy call is not healthy."
}

ensure_console_dependencies() {
  require node
  require npm
  cd "$CONSOLE_DIR"
  if [[ ! -d node_modules ]] \
    || { [[ -f package-lock.json ]] && [[ ! -f node_modules/.package-lock.json || package-lock.json -nt node_modules/.package-lock.json ]]; }; then
    log "Installing/updating console dependencies"
    if [[ -f package-lock.json ]]; then npm ci; else npm install; fi
  else
    ok "Console dependencies already match the lockfile"
  fi
  if [[ "$AUTO_RUN_UNIT_TESTS" == "true" ]]; then
    log "Running console unit tests"
    npm test
  fi
}

clean_local_runtime() {
  ensure_docker

  if curl -fsS --max-time 2 http://127.0.0.1:4174/api/health >/dev/null 2>&1 \
    || curl -fsS --max-time 2 http://127.0.0.1:5173/ >/dev/null 2>&1; then
    die "UI/BFF are still running. Stop the ./run.sh terminal with Ctrl+C, then run clean/fresh again."
  fi

  log "Removing local AI Gateway containers and persisted Compose volumes"
  (
    cd "$GATEWAY_HOME"
    docker compose \
      -p ai-gateway \
      --env-file configs/keys.env \
      down -v --remove-orphans
  )

  log "Removing generated demo artifacts and local proxy-key files"
  "$ROOT_DIR/scripts/demo.sh" clean
  rm -rf "$CONSOLE_DIR/node_modules/.vite"

  if [[ "$CLEAN_CONSOLE_DEPS" == "true" ]]; then
    log "Removing console dependencies because CLEAN_CONSOLE_DEPS=true"
    rm -rf "$CONSOLE_DIR/node_modules"
  fi

  ok "Local demo runtime was cleaned"
  printf '%s\n' \
    "Preserved:" \
    "  - AI Workspace provider/proxy/gateway resources" \
    "  - wso2apip-ai-gateway-1.1.0/configs/keys.env" \
    "  - wso2apip-ai-gateway-1.1.0/configs/workspace-secrets.env" \
    "  - bank-ai-security-console/.env"
}

start_console() {
  if curl -fsS --max-time 2 http://127.0.0.1:4174/api/health >/dev/null 2>&1 \
    && curl -fsS --max-time 2 http://127.0.0.1:5173/ >/dev/null 2>&1; then
    ok "UI/BFF are already running"
    printf '\nUI:  http://127.0.0.1:5173/\nBFF: http://127.0.0.1:4174/api/health\n'
    return 0
  fi
  ensure_console_dependencies
  log "Starting Banking AI Security Console"
  printf 'UI:  http://127.0.0.1:5173/\nBFF: http://127.0.0.1:4174/api/health\nPress Ctrl+C to stop the UI/BFF.\n\n'
  cd "$CONSOLE_DIR"
  exec npm run dev
}

main() {
  local command="${1:-start}"
  case "$command" in
    start) ;;
    check) CHECK_ONLY=true ;;
    clean)
      for cmd in curl docker; do require "$cmd"; done
      [[ -x "$ROOT_DIR/scripts/demo.sh" ]] || die "Missing executable scripts/demo.sh"
      clean_local_runtime
      return 0
      ;;
    fresh)
      for cmd in curl docker; do require "$cmd"; done
      [[ -x "$ROOT_DIR/scripts/demo.sh" ]] || die "Missing executable scripts/demo.sh"
      clean_local_runtime
      ;;
    -h|--help|help) usage; return 0 ;;
    *) usage >&2; die "Unknown run command: $command" ;;
  esac

  for cmd in curl jq python3 openssl shasum; do require "$cmd"; done
  [[ -f "$CHAIN_FILE" ]] || die "Missing policy chain: $CHAIN_FILE"
  [[ -x "$ROOT_DIR/scripts/demo.sh" ]] || die "Missing executable scripts/demo.sh"

  ensure_docker
  start_gateway

  local mode
  mode="$(file_env_value "$ENV_FILE" DEMO_MODE || true)"
  if workspace_registration_present; then
    if [[ "$mode" != "workspace" ]]; then
      log "Connected gateway registration detected; selecting Workspace mode automatically"
    fi
    configure_workspace_console_defaults
    mode="workspace"
  else
    [[ -n "$mode" ]] || mode="standalone"
  fi

  if [[ "$mode" == "workspace" ]]; then
    log "Recovering AI Workspace-connected demo"
    wait_for_workspace_resources
    ensure_provider_access_key
    ensure_workspace_chain
    if [[ "$PROVIDER_KEY_ROTATED" == "true" ]]; then
      log "Binding customer-ai-secure to the newly issued provider access key"
      repair_workspace_proxy "$(load_or_prompt_provider_key)"
    fi
    ensure_proxy_key_and_guardrails
    validate_positive_path
    # One final state check catches a late control-plane overwrite after the smoke tests.
    ensure_workspace_chain
    ok "Gateway + proxy + 17 guardrails + OpenAI are ready"
  else
    log "Standalone mode detected"
    if [[ ! -f "$KEY_FILE" ]]; then
      die "Standalone proxy key is missing. Run OPENAI_API_KEY=... ./scripts/demo.sh deploy-local once."
    fi
    (
      cd "$CONSOLE_DIR"
      GATEWAY_HOME="$GATEWAY_HOME" ENV_FILE="$ENV_FILE" ./scripts/sync-api-key.sh >/dev/null
    )
    ok "Standalone proxy key synchronized"
  fi

  if [[ "$CHECK_ONLY" == "true" ]]; then
    printf '\nEverything required for the demo is healthy. CHECK_ONLY=true, so the UI was not started.\n'
    return 0
  fi
  start_console
}

main "$@"
