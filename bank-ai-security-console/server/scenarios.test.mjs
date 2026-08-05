import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateScenario, getScenario, getScenarios } from './scenarios.mjs';
import { getRagScenarios } from './rag-scenarios.mjs';

test('the UI exposes every required banking security scenario', () => {
  const ids = new Set(getScenarios().map((scenario) => scenario.id));
  const required = [
    'positive-baseline','positive-benign-base64','positive-valid-url','positive-schema','positive-prompt-decorator',
    'positive-dlp-email-phone','positive-dlp-card','positive-dlp-iban','positive-secret-redaction','positive-private-key-redaction','positive-hiring-human-review',
    'negative-missing-api-key','negative-invalid-api-key','negative-canonical-direct','negative-system-prompt-paraphrase','negative-persona-dan',
    'negative-professional-authority','negative-canonical-base64','negative-canonical-double-base64','negative-canonical-unicode','negative-request-regex',
    'negative-sensitive-health','negative-harmful-self-harm','negative-harmful-violence','negative-high-impact-hiring','negative-excessive-reliance',
    'negative-model-typosquatting','negative-output-token-budget','negative-streaming-budget',
    'negative-plugin-escalation','negative-tool-typosquatting','negative-tool-description-poisoning','negative-self-asserted-agent-context','negative-agent-forged-delegation',
    'negative-agent-action-scope','negative-agent-action-approval',
    'negative-output-xss','negative-output-sql','negative-output-shell','negative-output-path-traversal','negative-output-markdown-exfiltration',
    'negative-response-regex-marker','negative-response-url','negative-schema',
  ];
  for (const id of required) assert.ok(ids.has(id), `missing scenario ${id}`);
});

test('response regex uses the deterministic non-secret demo marker', () => {
  const scenario = getScenario('negative-response-regex-marker');
  assert.match(scenario.payload.messages[0].content, /WSO2-RESPONSE-REGEX-DEMO-TRIGGER-7E3A9F/);
});

test('double Base64 case is actually nested twice', () => {
  const scenario = getScenario('negative-canonical-double-base64');
  const once = Buffer.from(scenario.payload.messages[0].content, 'base64').toString('utf8');
  const clear = Buffer.from(once, 'base64').toString('utf8');
  assert.match(clear, /Ignora todas las instrucciones anteriores/);
});

test('expected check evaluation confirms a matching guardrail response', () => {
  const scenario = getScenario('negative-response-url');
  const evaluation = evaluateScenario(scenario, { status: 422, body: { message: { check: 'url-validation' } } });
  assert.equal(evaluation.passed, true);
});

test('PII validator rejects disclosed values', () => {
  const scenario = getScenario('positive-dlp-email-phone');
  const evaluation = evaluateScenario(scenario, { status: 200, body: { choices: [{ message: { content: 'alice.demo@example.test' } }] } });
  assert.equal(evaluation.passed, false);
});

test('approved high-impact response must require human review', () => {
  const scenario = getScenario('positive-hiring-human-review');
  const evaluation = evaluateScenario(scenario, { status: 200, body: { choices: [{ message: { content: JSON.stringify({ answer: 'Review', confidence: 0.7, requiresHumanReview: true, sources: [] }) } }] } });
  assert.equal(evaluation.passed, true);
});


test('the protected RAG UI exposes every required assurance scenario', () => {
  const ids = new Set(getRagScenarios().map((scenario) => scenario.id));
  const required = [
    'rag-invalid-token',
    'rag-tenant-mismatch',
    'rag-rate-limit',
    'rag-clean-ingestion',
    'rag-poisoned-ingestion',
    'rag-invalid-signature',
    'rag-malicious-email',
    'rag-file-clean-upload','rag-file-poisoned-upload','rag-file-zero-width-upload','rag-file-active-content','rag-file-unsupported-format',
    'rag-protected-query',
    'rag-cross-tenant-leakage',
    'rag-ungrounded-evaluation',
    'rag-unsafe-bypass',
  ];
  for (const id of required) assert.ok(ids.has(id), `missing RAG scenario ${id}`);
});

test('trusted banking context remains server-side', () => {
  const baseline = getScenario('positive-baseline');
  const approved = getScenario('positive-agent-approved-action');

  assert.match(baseline.trustedContext, /DEMO-1001/);
  assert.match(approved.trustedContext, /APR-DEMO-1001/);

  const publicScenarios = new Map(
    getScenarios().map((scenario) => [scenario.id, scenario]),
  );

  assert.equal(
    'trustedContext' in publicScenarios.get('positive-baseline'),
    false,
  );
  assert.equal(
    'trustedContext' in publicScenarios.get('positive-agent-approved-action'),
    false,
  );
});

test('trusted-result validator rejects generic model disclaimers', () => {
  const scenario = getScenario('positive-agent-approved-action');

  const evaluation = evaluateScenario(scenario, {
    status: 200,
    body: {
      choices: [{
        message: {
          content: 'No tengo la capacidad para confirmar autorizaciones.',
        },
      }],
    },
  });

  assert.equal(evaluation.passed, false);
});

test('trusted-result validator accepts the approved authorization confirmation', () => {
  const scenario = getScenario('positive-agent-approved-action');

  const evaluation = evaluateScenario(scenario, {
    status: 200,
    body: {
      choices: [{
        message: {
          content: 'La autorización APR-DEMO-1001 fue validada. No se ejecutó ninguna transferencia.',
        },
      }],
    },
  });

  assert.equal(evaluation.passed, true);
});

test('agent authorization scenarios use server-side delegation evidence', () => {
  const approved = getScenario('positive-agent-approved-action');
  const forged = getScenario('negative-agent-forged-delegation');
  const deniedScope = getScenario('negative-agent-action-scope');
  const deniedApproval = getScenario('negative-agent-action-approval');
  for (const scenario of [approved, forged, deniedScope, deniedApproval]) {
    assert.ok(scenario.delegationContext, `${scenario.id} must have server-side delegation context`);
    assert.equal('securityContext' in scenario.payload, false, `${scenario.id} must not trust body authorization context`);
  }
  assert.equal(forged.delegationSignatureMode, 'invalid');
  const selfAsserted = getScenario('negative-self-asserted-agent-context');
  assert.ok(selfAsserted.payload.securityContext);
});
