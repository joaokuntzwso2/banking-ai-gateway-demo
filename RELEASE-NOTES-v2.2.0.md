# Release Notes — v2.2.0

## Security coverage added

- Exact model allowlisting and lookalike model rejection.
- Request and generation resource budgets.
- Tool/plugin allowlisting, poisoned-description detection, signed delegated scopes, and human-approval validation.
- Output-safety checks for active HTML/JavaScript, destructive SQL, dangerous shell commands, path traversal, and external Markdown-image requests.
- Real file-upload workflow in the Protected RAG lab.
- Strict text-file preflight with filename, size, extension/MIME, magic-byte, binary/NUL, UTF-8, JSON, active-content, control-character, zero-width, and SHA-256 checks.
- New UI scenarios and evidence views for supply-chain, cost-abuse, agent-authorization, improper-output, and file-ingestion risks.

## Architecture

The solution keeps every gateway concern in an independent Go module. The React browser calls a local Node BFF; the WSO2 proxy key and demonstration signing secrets stay server-side. Protected ingestion remains a separate API/service boundary for files, documents, email, provenance, quarantine, and tenant-aware retrieval.

## Important production boundaries

- The signed HMAC delegation envelope is a local API-key demo bridge. Production authorization should come from the gateway authentication context and must be revalidated by each tool/backend.
- PDF, Office, archives, images, and executables fail closed. Supporting them requires sandboxed parsing, malware scanning, decompression limits, CDR, OCR governance, and trusted text extraction.
- Output inspection is defense in depth; consuming applications still need safe rendering, SQL parameterization, no-shell execution, path validation, and egress controls.
- The RAG store is dependency-free and in-process for the demo. Production tenant enforcement belongs in the real vector store or row-level-security layer.
