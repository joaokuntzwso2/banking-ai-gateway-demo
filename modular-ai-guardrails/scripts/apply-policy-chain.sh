#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="${DEMO_HOME:-$(cd "$PACKAGE_ROOT/.." && pwd)}"
GATEWAY_HOME="${GATEWAY_HOME:-$DEMO_HOME/wso2apip-ai-gateway-1.1.0}"
PROXY_ID="${PROXY_ID:-customer-ai-secure}"
CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:9090}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
READY_ATTEMPTS="${READY_ATTEMPTS:-90}"
READY_INTERVAL_SECONDS="${READY_INTERVAL_SECONDS:-2}"
CHAIN_FILE="$PACKAGE_ROOT/config/modular-policy-chain.json"
DELEGATION_SECRET="${DEMO_DELEGATION_CONTEXT_SECRET:-aurelius-local-delegation-context-secret-change-me-2026}"
EFFECTIVE_CHAIN="/tmp/modular-policy-chain-effective-$$.json"
STAMP="$(date +%Y%m%d-%H%M%S)"
EVIDENCE_HOME="$DEMO_HOME/evidence"

mkdir -p "$EVIDENCE_HOME" "$GATEWAY_HOME/configs"
trap 'rm -f "$EFFECTIVE_CHAIN"' EXIT

if [[ ${#DELEGATION_SECRET} -lt 24 ]]; then
  echo "DEMO_DELEGATION_CONTEXT_SECRET must contain at least 24 characters." >&2
  exit 1
fi

jq --arg secret "$DELEGATION_SECRET" '
  map(
    if .name == "custom-agent-tool-scope-guardrail" then
      .paths |= map(.params.demoContextHmacSecret = $secret)
    else . end
  )
' "$CHAIN_FILE" > "$EFFECTIVE_CHAIN"
CURRENT="$EVIDENCE_HOME/${PROXY_ID}-before-modular-$STAMP.json"
UPDATED="/tmp/${PROXY_ID}-modular-$STAMP.json"
APPLIED="/tmp/${PROXY_ID}-applied-$STAMP.json"

wait_for_controller() {
  printf 'Waiting for Gateway Controller'
  for ((attempt=1; attempt<=READY_ATTEMPTS; attempt++)); do
    if curl -fsS --max-time 3 \
      -u "$ADMIN_USER:$ADMIN_PASSWORD" \
      -H 'Accept: application/json' \
      "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
      > "$CURRENT" 2>/dev/null; then
      printf ' ready\n'
      return 0
    fi
    printf '.'
    sleep "$READY_INTERVAL_SECONDS"
  done
  printf '\nGateway Controller did not become ready in time.\n' >&2
  return 1
}

wait_for_controller

jq --slurpfile chain "$EFFECTIVE_CHAIN" '
  del(.status)
  |
  .spec.policies = (
    [(.spec.policies // [])[] | select(.name == "api-key-auth")]
    + $chain[0]
    + [
        (.spec.policies // [])[]
        | select(
            .name != "api-key-auth"
            and .name != "canonicalize-and-classify"
            and .name != "unified-ai-guardrails"
            and .name != "prompt-decorator"
            and .name != "regex-guardrail"
            and .name != "url-guardrail"
            and .name != "json-schema-guardrail"
            and .name != "custom-request-regex-guardrail"
            and .name != "custom-prompt-decorator"
            and .name != "custom-request-block-finalizer"
            and .name != "custom-response-regex-guardrail"
            and .name != "custom-response-url-guardrail"
            and .name != "custom-response-json-schema-guardrail"
            and .name != "custom-jailbreak-intent-guardrail"
            and .name != "custom-request-dlp-redaction"
            and .name != "custom-harmful-content-guardrail"
            and .name != "custom-high-impact-decision-guardrail"
            and .name != "custom-sensitive-context-guardrail"
            and .name != "custom-reliance-guardrail"
            and .name != "custom-response-output-safety-guardrail"
            and .name != "custom-agent-tool-scope-guardrail"
            and .name != "custom-resource-budget-guardrail"
            and .name != "custom-model-allowlist-guardrail"
          )
      ]
  )
' "$CURRENT" > "$UPDATED"

printf 'Applying policy order:\n'
jq -r '.spec.policies[].name' "$UPDATED"

curl --fail-with-body -sS \
  -u "$ADMIN_USER:$ADMIN_PASSWORD" \
  -X PUT \
  "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data-binary "@$UPDATED" \
  > "$APPLIED"

jq '{name: .metadata.name, state: .status.state, policies: [.spec.policies[]?.name]}' "$APPLIED"

EXPECTED_POLICY_COUNT="$(jq 'length' "$EFFECTIVE_CHAIN")"
printf '\nWaiting for the modular chain to become readable'
chain_ready=false
for ((attempt=1; attempt<=READY_ATTEMPTS; attempt++)); do
  if curl -fsS --max-time 3 \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -H 'Accept: application/json' \
    "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID" \
    > /tmp/modular-chain-status.json 2>/dev/null \
    && jq -e --argjson expected "$EXPECTED_POLICY_COUNT" '
      ([.spec.policies[]?.name] | index("api-key-auth")) != null
      and (([.spec.policies[]?.name] | map(select(startswith("custom-") or . == "canonicalize-and-classify")) | length) >= $expected)
    ' /tmp/modular-chain-status.json >/dev/null; then
    chain_ready=true
    printf ' ready\n'
    break
  fi
  printf '.'
  sleep "$READY_INTERVAL_SECONDS"
done

if [[ "$chain_ready" != true ]]; then
  printf '\nThe modular policy chain did not become ready in time.\n' >&2
  exit 1
fi

KEY_NAME="modular-policies-$STAMP"
KEY_FILE="$GATEWAY_HOME/configs/${PROXY_ID}-modular-key-latest.json"
umask 077
jq -n --arg name "$KEY_NAME" '{name:$name}' > /tmp/modular-key-request.json

printf 'Generating a fresh proxy API key'
key_ready=false
for ((attempt=1; attempt<=30; attempt++)); do
  if curl --fail-with-body -sS --max-time 5 \
    -u "$ADMIN_USER:$ADMIN_PASSWORD" \
    -X POST \
    "$CONTROLLER_URL/api/management/v0.9/llm-proxies/$PROXY_ID/api-keys" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary @/tmp/modular-key-request.json \
    > "$KEY_FILE.tmp" 2>/dev/null \
    && jq -e --arg proxy "$PROXY_ID" '
      .status == "success"
      and .apiKey.status == "active"
      and .apiKey.apiId == $proxy
      and (.apiKey.apiKey | type == "string" and length > 0)
    ' "$KEY_FILE.tmp" >/dev/null; then
    mv "$KEY_FILE.tmp" "$KEY_FILE"
    key_ready=true
    printf ' ready\n'
    break
  fi
  printf '.'
  sleep 2
done
rm -f "$KEY_FILE.tmp"

if [[ "$key_ready" != true ]]; then
  printf '\nA fresh API key could not be generated.\n' >&2
  exit 1
fi

chmod 600 "$KEY_FILE"
KEY_FINGERPRINT="$(jq -er '.apiKey.apiKey' "$KEY_FILE" | shasum -a 256 | awk '{print substr($1,1,12)}')"
printf '\nFresh key created. Safe metadata:\n'
jq '{status,message,remainingApiKeyQuota,key:{name:.apiKey.name,status:.apiKey.status,apiId:.apiKey.apiId,length:(.apiKey.apiKey|length)}}' "$KEY_FILE"
printf 'fingerprint: %s\n' "$KEY_FINGERPRINT"
printf '\nSynchronize it into the UI with:\n'
printf 'cd %q && ./scripts/sync-api-key.sh\n' "$DEMO_HOME/bank-ai-security-console"
