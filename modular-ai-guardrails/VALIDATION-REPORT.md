# Validation Report

Version: 2.2.0

## Validated in the artifact build environment

- 27 passing Node backend tests, with zero failures.
- Scenario-registry checks for all 47 LLM/API scenarios and all 16 protected-RAG scenarios.
- File-ingestion tests covering clean UTF-8 acceptance, filename traversal rejection, PDF magic bytes disguised as text, active-content quarantine, zero-width evidence, and invalid UTF-8 rejection.
- Protected-RAG tests covering signed clean ingestion, poisoned-document and malicious-email quarantine, PII/PCI redaction, JWT verification, tenant mismatch, rate limiting, signature verification, accepted-only retrieval, cross-tenant isolation, groundedness failure, and the controlled evaluator-limitation path.
- Server-side delegation tests confirming that agent scenarios use signed server evidence rather than request-body authorization claims.
- Node syntax validation for every server `.mjs` module.
- TypeScript/TSX syntax transpilation for nine UI and Vite source files with zero syntax errors.
- Shell syntax validation for every installation, deployment, key-sync, RAG cURL, startup, and live-acceptance script.
- JSON parsing for all five JSON configuration files.
- YAML parsing for the protected-ingestion OpenAPI document and all 17 policy definitions: 18 YAML files total.
- Independent compilation of all 17 Go policy modules against local API-shape stubs matching the WSO2 SDK types used by the source. This checks the package/type surface but is not a substitute for the real `ap gateway image build`.
- Policy-chain consistency checks confirming that all 17 custom modules have source, `go.mod`, `policy-definition.yaml`, build registration, and proxy-chain configuration.
- Verified that the React source contains neither the unsupported Lucide `Trace` import nor generated runtime secrets.

## Package hygiene

The distributable archives are checked to exclude:

- `.env` files;
- generated proxy API-key JSON files;
- provider credentials;
- `node_modules` and build caches;
- persisted RAG state;
- temporary compile stubs;
- local evidence and backup directories.

The values present in `.env.example` and policy-chain configuration are explicitly labelled local-demo placeholders and must be replaced outside a controlled demonstration.

## Environment-dependent validation not claimed here

A full dependency installation and Vite production build were not executed in this build container because its configured npm registry did not provide the required public React type packages. The source-level syntax and backend tests passed, but the user should still run:

```bash
npm install
npm test
npm run build
```

A complete live certification also depends on external systems that are unavailable in the artifact build environment:

- the running WSO2 AI Gateway 1.1.0 image and current proxy revision;
- the real `ap gateway image build` against the installed SDK and policy builder;
- a freshly generated inbound proxy API key;
- provider access and model behavior;
- DNS and HTTP reachability from the gateway runtime;
- the configured Agent Manager/OTLP endpoint.

The included `scripts/test-modular-policies.sh` is the final live acceptance suite. It exercises authentication, model allowlisting, resource budgets, prompt attacks, encoding and Unicode, DLP, harmful and sensitive content, high-impact decisions, excessive reliance, plugin/tool controls, signed delegated authorization, output safety, URL validation, response leakage, and structured-output enforcement.
