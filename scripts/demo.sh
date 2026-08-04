#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONSOLE_DIR="$ROOT_DIR/bank-ai-security-console"
MODULAR_DIR="$ROOT_DIR/modular-ai-guardrails"
GATEWAY_HOME="$ROOT_DIR/wso2apip-ai-gateway-1.1.0"
ENV_FILE="$CONSOLE_DIR/.env"
KEY_FILE="$GATEWAY_HOME/configs/customer-ai-secure-modular-key-latest.json"
CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:9090}"
CONTROLLER_HEALTH_URL="${CONTROLLER_HEALTH_URL:-http://localhost:9094/health}"
RUNTIME_READY_URL="${RUNTIME_READY_URL:-http://localhost:9901/ready}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
PROXY_ID="${PROXY_ID:-customer-ai-secure}"
PROVIDER_ID="${PROVIDER_ID:-openai-provider}"

usage() {
  cat <<'EOF'
Usage: ./scripts/demo.sh <command>

Commands:
  doctor            Check required tools, files, ports, and tracked-risk files
  init              Create ignored local configuration, secrets, and TLS material
  build             Build custom gateway images and start the local runtime
  deploy-local      Initialize, build, create provider/proxy, apply policies, sync key
  quickstart-local  Run deploy-local and start the console
  workspace-config Configure the console for an AI Workspace Invoke URL and API key
  start             Install/test dependencies and start BFF + Vite
  unit-test         Run Node tests
  gateway-test      Run live modular gateway acceptance tests
  rag-test          Run protected-ingestion API acceptance tests
  test              Run unit, gateway, and RAG tests when their services are available
  status            Show gateway, BFF, UI, and port status
  stop              Stop gateway containers while preserving controller data
  clean             Remove generated local evidence/build/RAG/key artifacts
  reset-local       Destructive: remove gateway containers and persisted volumes

Environment used by selected commands:
  OPENAI_API_KEY             Required by deploy-local/quickstart-local
  AI_WORKSPACE_INVOKE_URL    Required by workspace-config
  AI_WORKSPACE_API_KEY       Required by workspace-config
  CONFIRM_RESET=YES          Required by reset-local
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

fingerprint() {
  printf '%s' "$1" | shasum -a 256 | awk '{print substr($1,1,12)}'
}

env_value() {
  local name="$1"
  python3 - "$ENV_FILE" "$name" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
wanted = sys.argv[2]
if not path.exists():
    raise SystemExit(0)

for line in path.read_text().splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue
    name, value = stripped.split("=", 1)
    if name.strip() != wanted:
        continue
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    print(value, end="")
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
result = []
for line in lines:
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        name = stripped.split("=", 1)[0].strip()
        if name in pairs:
            continue
    result.append(line)

while result and not result[-1].strip():
    result.pop()

result.extend(["", "# Managed by scripts/demo.sh"])
for name, value in pairs.items():
    result.append(f"{name}={value}")

path.write_text("\n".join(result) + "\n")
PY
  chmod 600 "$ENV_FILE"
}

new_secret() {
  openssl rand -hex 32
}

init_local() {
  for cmd in python3 openssl; do require "$cmd"; done

  mkdir -p \
    "$GATEWAY_HOME/configs" \
    "$GATEWAY_HOME/resources/listener-certs" \
    "$CONSOLE_DIR/data" \
    "$ROOT_DIR/evidence"

  if [[ ! -f "$GATEWAY_HOME/configs/config.toml" ]]; then
    cp "$GATEWAY_HOME/configs/config-template.toml" \
      "$GATEWAY_HOME/configs/config.toml"
  fi

  touch "$GATEWAY_HOME/configs/keys.env"
  touch "$GATEWAY_HOME/configs/embedding.env"
  chmod 600 \
    "$GATEWAY_HOME/configs/keys.env" \
    "$GATEWAY_HOME/configs/embedding.env" \
    "$GATEWAY_HOME/configs/config.toml"

  local cert="$GATEWAY_HOME/resources/listener-certs/default-listener.local.crt"
  local key="$GATEWAY_HOME/resources/listener-certs/default-listener.key"
  if [[ ! -s "$cert" || ! -s "$key" ]]; then
    echo "Generating local self-signed TLS material..."
    openssl req \
      -x509 \
      -newkey rsa:2048 \
      -sha256 \
      -nodes \
      -days 365 \
      -subj '/CN=localhost' \
      -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
      -keyout "$key" \
      -out "$cert" \
      >/dev/null 2>&1
    chmod 600 "$key"
  fi

  python3 - "$GATEWAY_HOME/configs/config.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.replace(
    'cert_path = "./listener-certs/default-listener.crt"',
    'cert_path = "./listener-certs/default-listener.local.crt"',
)
path.write_text(text)
PY

  if [[ ! -f "$ENV_FILE" ]]; then
    cp "$CONSOLE_DIR/.env.example" "$ENV_FILE"
  fi

  local delegation rag_jwt rag_signing
  delegation="$(env_value DEMO_DELEGATION_CONTEXT_SECRET || true)"
  rag_jwt="$(env_value RAG_JWT_SECRET || true)"
  rag_signing="$(env_value RAG_DEMO_SIGNING_SECRET || true)"

  [[ -n "$delegation" && "$delegation" != *replace* && "$delegation" != *change-me* ]] \
    || delegation="$(new_secret)"
  [[ -n "$rag_jwt" && "$rag_jwt" != *replace* && "$rag_jwt" != *change-me* ]] \
    || rag_jwt="$(new_secret)"
  [[ -n "$rag_signing" && "$rag_signing" != *replace* && "$rag_signing" != *change-me* ]] \
    || rag_signing="$(new_secret)"

  local mode gateway_url allow_self_signed
  mode="$(env_value DEMO_MODE || true)"
  gateway_url="$(env_value WSO2_GATEWAY_URL || true)"
  allow_self_signed="$(env_value WSO2_ALLOW_SELF_SIGNED || true)"

  [[ -n "$mode" ]] || mode="standalone"
  [[ -n "$gateway_url" ]] \
    || gateway_url="https://localhost:8443/customer-ai-secure/chat/completions"
  [[ -n "$allow_self_signed" ]] || allow_self_signed="true"

  set_env_values \
    "DEMO_MODE=$mode" \
    "WSO2_GATEWAY_URL=$gateway_url" \
    "WSO2_ALLOW_SELF_SIGNED=$allow_self_signed" \
    "DEMO_DELEGATION_CONTEXT_SECRET=$delegation" \
    "RAG_JWT_SECRET=$rag_jwt" \
    "RAG_DEMO_SIGNING_SECRET=$rag_signing"

  echo "Local configuration initialized."
  echo "Console environment: $ENV_FILE"
}

doctor() {
  local failed=0
  for cmd in git docker node npm ap go curl jq python3 openssl shasum; do
    if command -v "$cmd" >/dev/null 2>&1; then
      printf '%-10s %s\n' "$cmd" "$(command -v "$cmd")"
    else
      printf '%-10s MISSING\n' "$cmd"
      failed=1
    fi
  done

  echo
  echo "Required repository paths:"
  for path in \
    "$CONSOLE_DIR/package.json" \
    "$MODULAR_DIR/config/modular-policy-chain.json" \
    "$GATEWAY_HOME/build.yaml" \
    "$GATEWAY_HOME/docker-compose.yaml"; do
    if [[ -e "$path" ]]; then
      echo "OK      ${path#$ROOT_DIR/}"
    else
      echo "MISSING ${path#$ROOT_DIR/}"
      failed=1
    fi
  done

  echo
  echo "Ports:"
  for port in 5173 4174 8443 9090 9094 9901; do
    if command -v lsof >/dev/null 2>&1; then
      owner="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | tail -n +2 | head -1 || true)"
      if [[ -n "$owner" ]]; then
        echo "$port in use: $owner"
      else
        echo "$port free"
      fi
    fi
  done

  if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo
    echo "Tracked files that must not remain:"
    risky="$(
      git -C "$ROOT_DIR" ls-files |
      grep -E '(^|/)(customer-ai-hardened-local\.json|customer-ai-secure-with-custom-policy\.json|.*\.env|.*\.key|.*api-key.*\.json)$' \
      || true
    )"
    if [[ -n "$risky" ]]; then
      printf '%s\n' "$risky"
      failed=1
    else
      echo "None detected."
    fi

    echo
    visibility_note="Verify repository visibility and customer access in GitHub before sharing."
    echo "$visibility_note"
  fi

  [[ "$failed" == 0 ]] || die "Doctor found missing tools/files or tracked-risk artifacts."
}

build_gateway() {
  for cmd in ap docker curl; do require "$cmd"; done
  init_local
  (
    cd "$MODULAR_DIR"
    DEMO_HOME="$ROOT_DIR" \
    GATEWAY_HOME="$GATEWAY_HOME" \
      ./scripts/build-and-restart.sh
  )
}

wait_for_url() {
  local label="$1" url="$2" attempts="${3:-90}"
  printf 'Waiting for %s' "$label"
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      printf ' ready\n'
      return 0
    fi
    printf '.'
    sleep 2
  done
  printf '\n'
  die "$label did not become ready: $url"
}

post_yaml_accept_existing() {
  local url="$1" file="$2" label="$3"
  local body status
  body="$(mktemp)"
  status="$(
    curl -sS \
      -u "$ADMIN_USER:$ADMIN_PASSWORD" \
      -o "$body" \
      -w '%{http_code}' \
      -X POST "$url" \
      -H 'Content-Type: application/yaml' \
      -H 'Accept: application/json' \
      --data-binary "@$file" \
      || true
  )"

  case "$status" in
    200|201|202)
      echo "$label created."
      ;;
    409)
      echo "$label already exists."
      ;;
    *)
      echo "$label creation failed with HTTP $status." >&2
      cat "$body" >&2
      rm -f "$body"
      exit 1
      ;;
  esac
  rm -f "$body"
}

ensure_api_key_policy() {
  local current updated
  current="$(mktemp)"
  updated="$(mktemp)"

  curl -fsS \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -H 'Accept: application/json' \
    "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
    > "$current"

  if jq -e '.spec.policies[]? | select(.name == "api-key-auth")' \
    "$current" >/dev/null; then
    echo "Inbound API-key policy is already present."
    rm -f "$current" "$updated"
    return 0
  fi

  jq '
    del(.status)
    | .spec.policies = (
        [{
          name: "api-key-auth",
          version: "v1",
          paths: [{
            path: "/*",
            methods: ["*"],
            params: {in: "header", key: "Authorization"}
          }]
        }]
        + (.spec.policies // [])
      )
  ' "$current" > "$updated"

  curl --fail-with-body -sS \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -X PUT \
    "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary "@$updated" \
    >/dev/null

  rm -f "$current" "$updated"
  echo "Inbound API-key policy added."
}

bootstrap_local() {
  require curl
  require jq
  : "${OPENAI_API_KEY:?Set OPENAI_API_KEY before deploying standalone mode}"

  wait_for_url "Gateway Controller admin" "$CONTROLLER_HEALTH_URL"
  wait_for_url "Gateway Runtime" "$RUNTIME_READY_URL"

  local provider_yaml
  provider_yaml="$(mktemp)"
  chmod 600 "$provider_yaml"

  cat > "$provider_yaml" <<EOF
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: $PROVIDER_ID
spec:
  displayName: OpenAI Provider
  version: v1.0
  template: openai
  context: /openai/latest
  upstream:
    url: https://api.openai.com/v1
    auth:
      type: api-key
      header: Authorization
      value: $OPENAI_API_KEY
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
      - path: /models
        methods: [GET]
      - path: /models/{modelId}
        methods: [GET]
EOF

  if curl -fsS \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    "$CONTROLLER_URL/api/management/v0.9/llm-providers/$PROVIDER_ID" \
    >/dev/null 2>&1; then
    echo "LLM provider already exists."
  else
    post_yaml_accept_existing \
      "$CONTROLLER_URL/llm-providers" \
      "$provider_yaml" \
      "LLM provider"
  fi

  if curl -fsS \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
    >/dev/null 2>&1; then
    echo "LLM proxy already exists."
  else
    post_yaml_accept_existing \
      "$CONTROLLER_URL/llm-proxies" \
      "$GATEWAY_HOME/customer-ai-secure.yaml" \
      "LLM proxy"
  fi

  ensure_api_key_policy

  set_env_values \
    "DEMO_MODE=standalone" \
    "WSO2_GATEWAY_URL=https://localhost:8443/customer-ai-secure/chat/completions" \
    "WSO2_ALLOW_SELF_SIGNED=true"

  delegation="$(env_value DEMO_DELEGATION_CONTEXT_SECRET)"
  (
    cd "$MODULAR_DIR"
    DEMO_HOME="$ROOT_DIR" \
    GATEWAY_HOME="$GATEWAY_HOME" \
    DEMO_DELEGATION_CONTEXT_SECRET="$delegation" \
      ./scripts/apply-policy-chain.sh
  )

  (
    cd "$CONSOLE_DIR"
    GATEWAY_HOME="$GATEWAY_HOME" \
    ENV_FILE="$ENV_FILE" \
    DEMO_DELEGATION_CONTEXT_SECRET="$delegation" \
      ./scripts/sync-api-key.sh
  )

  rm -f "$provider_yaml"

  echo
  echo "Standalone gateway deployment completed."
  echo "Proxy key fingerprint: $(fingerprint "$(jq -er '.apiKey.apiKey' "$KEY_FILE")")"
}

deploy_local() {
  init_local
  build_gateway
  bootstrap_local
}

workspace_config() {
  require python3
  init_local
  : "${AI_WORKSPACE_INVOKE_URL:?Set AI_WORKSPACE_INVOKE_URL}"
  : "${AI_WORKSPACE_API_KEY:?Set AI_WORKSPACE_API_KEY}"

  full_endpoint="$(
    python3 - "$AI_WORKSPACE_INVOKE_URL" <<'PY'
import sys
url = sys.argv[1].strip().rstrip("/")
if url.endswith("/chat/completions"):
    print(url)
elif url.endswith("/v1"):
    print(url + "/chat/completions")
else:
    print(url + "/v1/chat/completions")
PY
  )"

  set_env_values \
    "DEMO_MODE=workspace" \
    "WSO2_GATEWAY_URL=$full_endpoint" \
    "WSO2_SECURE_API_KEY=$AI_WORKSPACE_API_KEY" \
    "WSO2_ALLOW_SELF_SIGNED=false"

  echo "AI Workspace console configuration written."
  echo "Endpoint: $full_endpoint"
  echo "Key fingerprint: $(fingerprint "$AI_WORKSPACE_API_KEY")"
}

start_console() {
  require node
  require npm
  require curl
  init_local

  mode="$(env_value DEMO_MODE || true)"
  if [[ "$mode" == "standalone" ]]; then
    [[ -f "$KEY_FILE" ]] || die "Standalone proxy key is missing. Run ./scripts/demo.sh deploy-local"
    delegation="$(env_value DEMO_DELEGATION_CONTEXT_SECRET)"
    (
      cd "$CONSOLE_DIR"
      GATEWAY_HOME="$GATEWAY_HOME" \
      ENV_FILE="$ENV_FILE" \
      DEMO_DELEGATION_CONTEXT_SECRET="$delegation" \
        ./scripts/sync-api-key.sh
    )
  else
    [[ -n "$(env_value WSO2_SECURE_API_KEY || true)" ]] \
      || die "AI Workspace key is missing. Run workspace-config."
  fi

  cd "$CONSOLE_DIR"
  if [[ -f package-lock.json ]]; then
    npm ci
  else
    npm install
  fi
  npm test

  echo
  echo "UI:  http://localhost:5173"
  echo "BFF: http://localhost:4174/api/health"
  echo "Press Ctrl+C to stop."
  exec npm run dev
}

unit_test() {
  require npm
  cd "$CONSOLE_DIR"
  if [[ -f package-lock.json ]]; then npm ci; else npm install; fi
  npm test
}

gateway_test() {
  require jq
  require curl
  require python3
  [[ -f "$ENV_FILE" ]] || die "Console .env is missing. Run init/deploy/workspace-config."

  key="$(env_value WSO2_SECURE_API_KEY || true)"
  url="$(env_value WSO2_GATEWAY_URL || true)"
  delegation="$(env_value DEMO_DELEGATION_CONTEXT_SECRET || true)"

  [[ -n "$key" ]] || die "WSO2_SECURE_API_KEY is empty."
  [[ -n "$url" ]] || die "WSO2_GATEWAY_URL is empty."

  (
    cd "$MODULAR_DIR"
    WSO2_SECURE_API_KEY="$key" \
    PROXY_URL="$url" \
    DEMO_DELEGATION_CONTEXT_SECRET="$delegation" \
      ./scripts/test-modular-policies.sh
  )
}

rag_test() {
  require curl
  curl -fsS --max-time 3 http://127.0.0.1:4174/api/health >/dev/null \
    || die "The BFF is not running on port 4174. Start the console first."
  (
    cd "$CONSOLE_DIR"
    ./scripts/rag-demo-curls.sh
  )
}

all_tests() {
  unit_test
  gateway_test
  if curl -fsS --max-time 2 http://127.0.0.1:4174/api/health >/dev/null 2>&1; then
    rag_test
  else
    echo "Skipping RAG curl suite because the BFF is not running."
  fi
}

status() {
  echo "== Gateway containers =="
  (
    cd "$GATEWAY_HOME"
    docker compose \
      -p ai-gateway \
      --env-file configs/keys.env \
      ps -a
  ) || true

  echo
  for item in \
    "Controller:$CONTROLLER_HEALTH_URL" \
    "Runtime:$RUNTIME_READY_URL" \
    "BFF:http://127.0.0.1:4174/api/health" \
    "UI:http://127.0.0.1:5173/"; do
    label="${item%%:*}"
    url="${item#*:}"
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      echo "$label: reachable"
    else
      echo "$label: unavailable"
    fi
  done

  if [[ -f "$ENV_FILE" ]]; then
    echo
    echo "Demo mode: $(env_value DEMO_MODE || true)"
    echo "Endpoint:  $(env_value WSO2_GATEWAY_URL || true)"
  fi
}

stop_gateway() {
  cd "$GATEWAY_HOME"
  docker compose \
    -p ai-gateway \
    --env-file configs/keys.env \
    down
  echo "Gateway stopped; controller data was preserved."
  echo "Stop the foreground UI/BFF with Ctrl+C in its terminal."
}

clean_generated() {
  rm -rf \
    "$ROOT_DIR/evidence" \
    "$CONSOLE_DIR/dist" \
    "$CONSOLE_DIR/coverage" \
    "$CONSOLE_DIR/data/rag-security-lab.json"
  find "$GATEWAY_HOME/configs" -maxdepth 1 -type f \
    \( -name '*-key*.json' -o -name '*api-key*.json' \) \
    -delete 2>/dev/null || true
  echo "Generated evidence, build output, RAG state, and proxy-key files removed."
}

reset_local() {
  [[ "${CONFIRM_RESET:-}" == "YES" ]] \
    || die "Set CONFIRM_RESET=YES to remove local gateway volumes."

  cd "$GATEWAY_HOME"
  docker compose \
    -p ai-gateway \
    --env-file configs/keys.env \
    down -v --remove-orphans

  clean_generated
  echo "Standalone gateway state reset. Run deploy-local again."
}

command="${1:-}"
case "$command" in
  doctor) doctor ;;
  init) init_local ;;
  build) build_gateway ;;
  deploy-local) deploy_local ;;
  quickstart-local) deploy_local; start_console ;;
  workspace-config) workspace_config ;;
  start) start_console ;;
  unit-test) unit_test ;;
  gateway-test) gateway_test ;;
  rag-test) rag_test ;;
  test) all_tests ;;
  status) status ;;
  stop) stop_gateway ;;
  clean) clean_generated ;;
  reset-local) reset_local ;;
  -h|--help|help|"") usage ;;
  *) usage; die "Unknown command: $command" ;;
esac
