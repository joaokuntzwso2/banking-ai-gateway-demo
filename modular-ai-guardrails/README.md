# Modular AI Guardrails for WSO2 AI Gateway 1.1.0

This package contains 17 independent custom Go policy modules. There is no active unified policy.

The authoritative source is:

```text
modular-ai-guardrails/policies/
```

`wso2apip-ai-gateway-1.1.0/build.yaml` references this directory directly; no copied root-level policy tree is required.

## Lifecycle

Use the root orchestrator:

```bash
cd <repository-root>
./scripts/demo.sh build
./scripts/demo.sh deploy-local
./scripts/demo.sh gateway-test
```

Focused helpers retained in this package:

```text
scripts/build-and-restart.sh
scripts/apply-policy-chain.sh
scripts/test-modular-policies.sh
```

- `build-and-restart.sh` builds the custom images, starts Docker Compose, and waits for Controller/Runtime health.
- `apply-policy-chain.sh` is for standalone Controller API deployments. It applies the ordered chain and creates a fresh proxy key.
- `test-modular-policies.sh` runs live acceptance against a deployed proxy.

Do not run `apply-policy-chain.sh` against an AI Workspace-managed proxy. In AI Workspace mode, sync the gateway policy manifest, attach policies in the UI, and redeploy the resource.

## Policy order

1. `api-key-auth`
2. `custom-model-allowlist-guardrail`
3. `custom-resource-budget-guardrail`
4. `canonicalize-and-classify`
5. `custom-jailbreak-intent-guardrail`
6. `custom-request-regex-guardrail`
7. `custom-request-dlp-redaction`
8. `custom-harmful-content-guardrail`
9. `custom-high-impact-decision-guardrail`
10. `custom-sensitive-context-guardrail`
11. `custom-reliance-guardrail`
12. `custom-agent-tool-scope-guardrail`
13. `custom-prompt-decorator`
14. `custom-request-block-finalizer`
15. `custom-response-regex-guardrail`
16. `custom-response-output-safety-guardrail`
17. `custom-response-url-guardrail`
18. `custom-response-json-schema-guardrail`

Policy parameters are defined in `config/modular-policy-chain.json`.

For the complete architecture, setup, AI Workspace procedure, and limitations, see the repository root `README.md`.
