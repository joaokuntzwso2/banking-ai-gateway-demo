# Complete Demo Coverage Matrix — v2.2.0

Controls are assigned to the component that can enforce them correctly. LLM proxy controls are independent WSO2 custom-policy modules. File, document, email, provenance, quarantine, and retrieval controls belong to the protected-ingestion service, which should itself be exposed through WSO2 API Platform.

## LLM endpoint and application scenarios

| Security objective | UI scenarios | Enforcement owner | Boundary |
|---|---|---|---|
| Approved endpoint flow | `positive-baseline` | Complete ordered chain | Covered |
| Model supply-chain allowlist | `positive-approved-model`, `negative-model-typosquatting` | `custom-model-allowlist-guardrail` | Validates requested identifier; provider deployment attestation is separate |
| Resource/cost limits | `positive-bounded-request`, `negative-output-token-budget`, `negative-streaming-budget` | `custom-resource-budget-guardrail` | Request-side budget; distributed quotas/rate limits remain platform controls |
| Direct injection | `negative-canonical-direct` | `canonicalize-and-classify` | Covered for configured patterns |
| Prompt extraction paraphrase | `negative-system-prompt-paraphrase` | `custom-jailbreak-intent-guardrail` | Deterministic demo intent classifier |
| Persona switching | `negative-persona-dan` | Canonicalization, jailbreak intent, Regex | Covered |
| Professional-authority bypass | `negative-professional-authority` | `custom-jailbreak-intent-guardrail` | Natural-language authority is not authorization |
| Encoding/obfuscation | `positive-benign-base64`, `negative-canonical-base64`, `negative-canonical-double-base64`, `negative-canonical-unicode` | `canonicalize-and-classify` | Decode depth two; zero-width normalization |
| PII/PCI/financial data | `positive-dlp-email-phone`, `positive-dlp-card`, `positive-dlp-iban` | `custom-request-dlp-redaction` | Structured DLP; contextual taxonomy requires enterprise classifier |
| Secret exfiltration | `positive-secret-redaction`, `positive-private-key-redaction`, `negative-response-regex-marker` | Request DLP and response Regex | Deterministic response trigger avoids model masking |
| Employee health/family | `negative-sensitive-health` | `custom-sensitive-context-guardrail` | Configured banking demo taxonomy |
| Harmful content | `negative-harmful-self-harm`, `negative-harmful-violence` | `custom-harmful-content-guardrail` | Minimal non-graphic deterministic classification |
| High-impact hiring | `negative-high-impact-hiring`, `positive-hiring-human-review` | High-impact policy and JSON Schema | JSON shape is not a fairness control |
| Excessive reliance | `negative-excessive-reliance` | Reliance policy and prompt decorator | Groundedness is evaluated separately in RAG lab |
| Plugin/tool escalation | `negative-plugin-escalation`, `negative-tool-typosquatting` | `custom-agent-tool-scope-guardrail` | Exact endpoint allowlist |
| Poisoned tool metadata | `negative-tool-description-poisoning` | `custom-agent-tool-scope-guardrail` | Deterministic suspicious-description classifier |
| Untrusted authorization claims | `negative-self-asserted-agent-context`, `negative-agent-forged-delegation` | `custom-agent-tool-scope-guardrail` | Body claims rejected; signed context verified |
| Agent scope/approval | `positive-agent-approved-action`, `negative-agent-action-scope`, `negative-agent-action-approval` | WSO2 AuthContext or signed demo context | Tool/backend must independently authorize the actual action |
| Improper output handling | `negative-output-xss`, `negative-output-sql`, `negative-output-shell`, `negative-output-path-traversal`, `negative-output-markdown-exfiltration` | `custom-response-output-safety-guardrail` | Downstream encoding, SQL parameterization, no-shell execution, path and egress controls still required |
| Valid/untrusted URLs | `positive-valid-url`, `negative-response-url` | Response URL policy | Reachability is not reputation |
| System canary | `positive-prompt-decorator`, `negative-response-regex-marker` | Prompt decorator and response Regex | Covered |
| Structured responses | `positive-schema`, `negative-schema` | Response JSON Schema | Conditional when JSON is requested |
| Inbound authentication | `negative-missing-api-key`, `negative-invalid-api-key` | `api-key-auth` | Covered |

## Protected ingestion and RAG

| Security objective | UI/API case | Enforcement owner | Boundary |
|---|---|---|---|
| Invalid JWT and tenant mismatch | `rag-invalid-token`, `rag-tenant-mismatch` | Protected-ingestion JWT verifier | Local HS256 demo; production issuer/JWKS required |
| Rate limits | `rag-rate-limit` | Ingestion service demo limiter | Production distributed policy belongs at gateway/service layer |
| Signed clean document | `rag-clean-ingestion` | Source trust, hash, signature, provenance | Covered |
| Poisoned document | `rag-poisoned-ingestion` | Source trust, contradiction, indirect-injection classifier, quarantine | Covered |
| Tampered signed source | `rag-invalid-signature` | Signature verification | Covered |
| Malicious email | `rag-malicious-email` | Sender trust, DLP, indirect-injection classifier | Covered |
| Real clean file upload | `rag-file-clean-upload` and file picker | Strict file preflight, signature simulation, ingestion pipeline | Covered |
| Poisoned file upload | `rag-file-poisoned-upload` | File preflight plus indirect-injection/source-trust quarantine | Covered |
| Zero-width file attack | `rag-file-zero-width-upload` | File evidence plus ingestion canonicalization | Covered |
| Active HTML in file | `rag-file-active-content` | File preflight quarantine | Covered |
| File type spoofing | `rag-file-unsupported-format` | Magic-byte validation | PDF bytes disguised as `.txt` are rejected |
| Filename traversal | Unit-tested file preflight | Canonical filename validation | Covered in automated backend tests |
| Invalid UTF-8/binary | Unit-tested file preflight | Fatal UTF-8 decoder, NUL and magic-byte checks | Covered in automated backend tests |
| Protected query | `rag-protected-query` | Accepted-only tenant-filtered retrieval | Covered |
| Cross-tenant leakage | `rag-cross-tenant-leakage` | Tenant filter before ranking | Production enforcement belongs in actual vector store/RLS |
| Groundedness | `rag-ungrounded-evaluation` | Evaluator | Detects unsupported answer; does not prove source trust |
| Poisoned-context evaluator limitation | `rag-unsafe-bypass` | Server-internal labelled simulation | Public bypass disabled |
| Trace evidence | Every RAG scenario | Local trace and optional OTLP export | External Agent Manager endpoint requires configuration |

## File-upload production requirements

The demo accepts only strict UTF-8 TXT, Markdown, JSON, and CSV. Enabling PDF, Office, archives, or images requires a sandboxed parser, malware scanning, decompression limits, content disarm/reconstruction, OCR governance, and trusted text extraction. The public file API does not treat `X-Upload-Channel` as authorization; publisher status must come from verified identity/roles and signatures.
