# Bank AI Security Console

React/TypeScript UI and Node.js/Express BFF for the Banking AI Gateway Security Demo.

The browser never receives the real WSO2 proxy key, RAG JWT secret, document-signing secret, or delegated-action secret. Those values remain in the server-side `.env`.

## Responsibilities

- Scenario Laboratory for 47 LLM/API controls
- Protected RAG lab with 16 guided scenarios
- Real UTF-8 file upload and preflight
- Server-side WSO2 invocation
- Signed local delegated-action envelopes
- Tenant JWT minting/verification for the RAG demo
- Accepted/quarantined knowledge state
- Optional OTLP HTTP JSON trace export

## Development

Use the root lifecycle script:

```bash
cd <repository-root>
./scripts/demo.sh start
```

Open `http://localhost:5173`.

## Tests

```bash
cd <repository-root>
./scripts/demo.sh unit-test
./scripts/demo.sh rag-test
```

The RAG curl suite requires the BFF to be running.

## Direct component commands

```bash
cp .env.example .env
npm ci
npm test
npm run dev
```

Vite runs strictly on `127.0.0.1:5173`; the BFF runs on `4174`.

## Protected ingestion API

```text
POST /protected-ingestion/v1/documents
POST /protected-ingestion/v1/emails
POST /protected-ingestion/v1/files
POST /protected-ingestion/v1/query
```

See `openapi/protected-ingestion.yaml`.

## Security boundary

The browser's governance-publisher selection is a local operator simulation. The public ingestion route independently verifies tenant identity, metadata, provenance, and signatures. Production deployments must replace local HMAC/HS256 demonstrators with enterprise identity, key management, malware scanning, and durable tenant-isolated storage.

For full setup, AI Workspace instructions, architecture, and troubleshooting, see the repository root `README.md`.
