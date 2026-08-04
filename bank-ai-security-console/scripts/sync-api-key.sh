#!/usr/bin/env bash
set -euo pipefail

CONSOLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="${DEMO_HOME:-$(cd "$CONSOLE_ROOT/.." && pwd)}"
GATEWAY_HOME="${GATEWAY_HOME:-$DEMO_HOME/wso2apip-ai-gateway-1.1.0}"
PROXY_ID="${PROXY_ID:-customer-ai-secure}"
KEY_FILE="${KEY_FILE:-$GATEWAY_HOME/configs/${PROXY_ID}-modular-key-latest.json}"
ENV_FILE="${ENV_FILE:-$CONSOLE_ROOT/.env}"
UI_API_URL="${UI_API_URL:-http://localhost:${PORT:-4174}}"
DELEGATION_SECRET="${DEMO_DELEGATION_CONTEXT_SECRET:-aurelius-local-delegation-context-secret-change-me-2026}"

[[ -f "$KEY_FILE" ]] || {
  echo "API key file not found: $KEY_FILE" >&2
  exit 1
}

jq -e --arg proxy "$PROXY_ID" '
  .status == "success"
  and .apiKey.status == "active"
  and .apiKey.apiId == $proxy
  and (.apiKey.apiKey | type == "string" and length > 0)
' "$KEY_FILE" >/dev/null || {
  echo "The key file does not contain an active key for proxy '$PROXY_ID'." >&2
  echo "Re-run modular-ai-guardrails/scripts/apply-policy-chain.sh." >&2
  exit 1
}

KEY="$(jq -er '.apiKey.apiKey' "$KEY_FILE")"

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$CONSOLE_ROOT/.env.example" "$ENV_FILE"
fi

python3 - "$ENV_FILE" "$KEY" "$DELEGATION_SECRET" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
key = sys.argv[2]
delegation_secret = sys.argv[3]

managed = {
    "WSO2_SECURE_API_KEY": key,
    "DEMO_DELEGATION_CONTEXT_SECRET": delegation_secret,
}

lines = path.read_text().splitlines() if path.exists() else []
result = []
for line in lines:
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        name = stripped.split("=", 1)[0].strip()
        if name in managed:
            continue
    result.append(line)

while result and not result[-1].strip():
    result.pop()

result.extend(["", "# Managed by scripts/sync-api-key.sh"])
for name, value in managed.items():
    result.append(f"{name}={value}")

path.write_text("\n".join(result) + "\n")
PY

chmod 600 "$ENV_FILE"

COUNT="$(
  python3 - "$ENV_FILE" <<'PY'
from pathlib import Path
import sys
count = 0
for line in Path(sys.argv[1]).read_text().splitlines():
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        if stripped.split("=", 1)[0].strip() == "WSO2_SECURE_API_KEY":
            count += 1
print(count)
PY
)"

[[ "$COUNT" == "1" ]] || {
  echo "Expected exactly one WSO2_SECURE_API_KEY entry; found $COUNT." >&2
  exit 1
}

FINGERPRINT="$(printf '%s' "$KEY" | shasum -a 256 | awk '{print substr($1,1,12)}')"
echo "Updated $ENV_FILE from $KEY_FILE (length=${#KEY}, fingerprint=$FINGERPRINT)"

if curl -fsS --max-time 2 "$UI_API_URL/api/health" \
  >/tmp/aurelius-ui-health.json 2>/dev/null; then
  jq '{status,gatewayReachable,apiKeyConfigured,endpoint}' \
    /tmp/aurelius-ui-health.json
else
  echo "UI backend is not running yet. Start it with: ./scripts/demo.sh start"
fi
