import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { RagSecurityLab, createJwtTenantAuth, createTenantTokenMap } from './rag-lab.mjs';
import { CLEAN_DOCUMENT, MALICIOUS_EMAIL, POISONED_DOCUMENT } from './rag-scenarios.mjs';

function createLab(overrides = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rag-lab-'));
  return new RagSecurityLab({
    dataFile: path.join(directory, 'state.json'),
    invokeLlm: async () => ({
      status: 200,
      body: { choices: [{ message: { content: 'El horario oficial de soporte es de lunes a viernes de 09:00 a 18:00.' } }] },
      durationMs: 12,
      correlationId: 'test-correlation',
    }),
    tenantTokens: createTenantTokenMap({ tenantAToken: 'token-a', tenantBToken: 'token-b' }),
    allowUnsafeSimulation: true,
    ...overrides,
  });
}

const authA = 'Bearer token-a';
const authB = 'Bearer token-b';

test('accepts trusted clean knowledge with provenance and ownership', async () => {
  const lab = createLab();
  const result = await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  assert.equal(result.status, 201);
  assert.equal(result.body.decision, 'ACCEPT');
  assert.equal(lab.getStatus().acceptedCount, 1);
  assert.equal(lab.getStatus().accepted[0].owner, CLEAN_DOCUMENT.owner);
});

test('quarantines poisoned knowledge with all demo signals', async () => {
  const lab = createLab();
  await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  const result = await lab.ingest({ authorization: authA, document: POISONED_DOCUMENT });
  assert.equal(result.status, 202);
  assert.equal(result.body.decision, 'QUARANTINE');
  assert.ok(result.body.reasons.includes('SOURCE_NOT_TRUSTED'));
  assert.ok(result.body.reasons.includes('INDIRECT_PROMPT_INJECTION'));
  assert.ok(result.body.reasons.includes('CONTRADICTS_APPROVED_SOURCE'));
});

test('quarantines malicious email before indexing', async () => {
  const lab = createLab();
  const result = await lab.ingestEmail({ authorization: authA, email: MALICIOUS_EMAIL });
  assert.equal(result.status, 202);
  assert.equal(result.body.decision, 'QUARANTINE');
  assert.ok(result.body.reasons.includes('SENDER_NOT_TRUSTED'));
  assert.ok(result.body.reasons.includes('INDIRECT_PROMPT_INJECTION'));
  assert.equal(lab.getStatus().quarantinedEmailCount, 1);
});

test('redacts PII and PCI before accepted storage', async () => {
  const lab = createLab();
  const document = {
    ...CLEAN_DOCUMENT,
    documentId: 'DOC-DLP-001',
    content: 'Contacta alice.demo@example.test, +14155550123 y usa 4111 1111 1111 1111.',
  };
  const result = await lab.ingest({ authorization: authA, document });
  assert.equal(result.body.decision, 'ACCEPT');
  assert.equal(result.body.dlp.findingCount, 3);
  const stored = lab.getStatus().accepted.find((item) => item.documentId === document.documentId);
  assert.ok(stored.content.includes('*****'));
  assert.ok(!stored.content.includes('alice.demo@example.test'));
});

test('rejects tenant mismatch', async () => {
  const lab = createLab();
  const result = await lab.ingest({ authorization: authB, document: CLEAN_DOCUMENT });
  assert.equal(result.status, 403);
});

test('validates signed JWT tenant tokens', async () => {
  const auth = createJwtTenantAuth({ secret: 'aurelius-test-jwt-secret-1234567890' });
  const tokenA = auth.mint('tenant-a');
  const lab = createLab({ tenantTokens: new Map(), tokenVerifier: (token) => auth.verify(token) });
  const result = await lab.ingest({ authorization: `Bearer ${tokenA}`, document: CLEAN_DOCUMENT });
  assert.equal(result.status, 201);
  const wrongTenant = await lab.query({ authorization: `Bearer ${tokenA}`, tenantId: 'tenant-b', question: 'horario', mode: 'protected' });
  assert.equal(wrongTenant.status, 403);
});

test('enforces per-tenant rate limiting', async () => {
  const lab = createLab({ rateLimit: { max: 1, windowMs: 60_000 } });
  const first = await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  const second = await lab.ingest({ authorization: authA, document: { ...CLEAN_DOCUMENT, documentId: 'DOC-SECOND' } });
  assert.equal(first.status, 201);
  assert.equal(second.status, 429);
});


test('enforces optional trusted document signatures', async () => {
  const signingKey = 'local-signing-key-for-aurelius-demo';
  const signature = crypto.createHmac('sha256', signingKey).update(CLEAN_DOCUMENT.content, 'utf8').digest('hex');
  const lab = createLab({ requireSignatures: true, trustedSigningKeys: { 'knowledge-key-1': signingKey } });
  const missing = await lab.ingest({ authorization: authA, document: { ...CLEAN_DOCUMENT, documentId: 'DOC-UNSIGNED' } });
  assert.equal(missing.body.decision, 'QUARANTINE');
  assert.ok(missing.body.reasons.includes('SIGNATURE_REQUIRED'));
  const valid = await lab.ingest({ authorization: authA, document: { ...CLEAN_DOCUMENT, documentId: 'DOC-SIGNED', signature: { keyId: 'knowledge-key-1', value: signature } } });
  assert.equal(valid.body.decision, 'ACCEPT');
  assert.equal(valid.body.provenance.signature.status, 'VALID');
});

test('protected query retrieves only accepted tenant knowledge', async () => {
  const lab = createLab();
  await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  await lab.ingest({ authorization: authA, document: POISONED_DOCUMENT });
  const result = await lab.query({ authorization: authA, tenantId: 'tenant-a', question: '¿Cuál es el horario oficial de soporte?', mode: 'protected' });
  assert.equal(result.status, 200);
  assert.equal(result.body.retrievedContext.length, 1);
  assert.equal(result.body.retrievedContext[0].documentId, CLEAN_DOCUMENT.documentId);
  assert.equal(result.body.securityConclusion, 'PROTECTED_RAG_FLOW_CONFIRMED');
  assert.equal(result.body.evaluations.groundedness.passed, true);
});

test('tenant-b cannot retrieve tenant-a context', async () => {
  const lab = createLab();
  await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  const result = await lab.query({ authorization: authB, tenantId: 'tenant-b', question: '¿Cuál es el horario oficial de soporte?', mode: 'protected' });
  assert.equal(result.status, 200);
  assert.equal(result.body.retrievedContext.length, 0);
  assert.equal(result.body.evaluations.tenantIsolation.passed, true);
});

test('groundedness catches unsupported 24-hour answer', async () => {
  const lab = createLab();
  await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  const result = await lab.query({ authorization: authA, tenantId: 'tenant-a', question: '¿Cuál es el horario oficial de soporte?', mode: 'ungrounded-simulation' });
  assert.equal(result.body.evaluations.groundedness.passed, false);
  assert.equal(result.body.securityConclusion, 'UNGROUNDED_ANSWER_DETECTED');
});

test('unsafe bypass shows evaluators cannot replace source trust controls', async () => {
  const lab = createLab();
  await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  await lab.ingest({ authorization: authA, document: POISONED_DOCUMENT });
  const result = await lab.query({ authorization: authA, tenantId: 'tenant-a', question: '¿Cuál es el horario oficial de soporte?', mode: 'unsafe-quarantine-bypass' });
  assert.equal(result.body.evaluations.sourceIntegrity.passed, false);
  assert.equal(result.body.securityConclusion, 'POISONED_SOURCE_RETRIEVED');
});

test('public unsafe bypass remains disabled unless explicitly enabled', async () => {
  const lab = createLab({ allowUnsafeSimulation: false });
  await lab.ingest({ authorization: authA, document: CLEAN_DOCUMENT });
  await lab.ingest({ authorization: authA, document: POISONED_DOCUMENT });
  const blocked = await lab.query({ authorization: authA, tenantId: 'tenant-a', question: '¿Cuál es el horario oficial de soporte?', mode: 'unsafe-quarantine-bypass' });
  assert.equal(blocked.status, 403);
  const internal = await lab.query({ authorization: authA, tenantId: 'tenant-a', question: '¿Cuál es el horario oficial de soporte?', mode: 'unsafe-quarantine-bypass', allowUnsafeSimulationOverride: true });
  assert.equal(internal.status, 200);
  assert.equal(internal.body.securityConclusion, 'POISONED_SOURCE_RETRIEVED');
});
