export type ScenarioCategory = 'allowed' | 'blocked' | 'access';

export interface Scenario {
  id: string;
  category: ScenarioCategory;
  title: string;
  summary: string;
  policy: string;
  expectedStatuses: number[];
  expectedCheck: string | null;
  assurance: string;
  payload: Record<string, unknown>;
}

export interface HealthStatus {
  status: 'ready' | 'degraded';
  gatewayReachable: boolean;
  apiKeyConfigured: boolean;
  endpoint: string;
  model: string;
  environment: string;
  policies: string[];
  rag?: RagStatus;
}

export interface InvocationResult {
  status: number;
  statusText: string;
  category: 'allowed' | 'blocked' | 'unauthorized' | 'error';
  durationMs: number;
  correlationId: string;
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: Record<string, unknown>;
    authMode: 'valid' | 'none' | 'invalid';
  };
  curl: string;
}

export interface ScenarioEvaluation {
  passed: boolean;
  statusMatched: boolean;
  checkMatched: boolean;
  customMatched: boolean;
  detail: string;
}

export interface ScenarioRunResponse {
  scenario: Scenario;
  result: InvocationResult;
  evaluation: ScenarioEvaluation;
}

export interface AuditEntry {
  id: string;
  scenarioId: string;
  title: string;
  category: ScenarioCategory | 'manual';
  passed: boolean;
  status: number;
  check: string | null;
  durationMs: number;
  timestamp: string;
  correlationId: string;
}

export type RagScenarioCategory = 'positive' | 'negative' | 'evidence';

export interface RagScenario {
  id: string;
  category: RagScenarioCategory;
  title: string;
  summary: string;
  action: string;
  expected: string;
  control: string;
}

export interface RagDlpResult {
  redactedContent?: string;
  findingCount: number;
  findings: Array<{ type: string; count: number }>;
}

export interface RagProvenance {
  trustedSource?: boolean;
  owner?: string;
  declaredSha256?: string | null;
  calculatedSha256?: string;
  declaredHashVerifiable?: boolean;
  hashMatches?: boolean | null;
  signature?: {
    status: string;
    keyId?: string | null;
  };
}

export interface RagDocument {
  kind: 'document' | 'email';
  resourceId: string;
  tenantId: string;
  documentId: string | null;
  messageId: string | null;
  sender: string | null;
  subject: string | null;
  source: string;
  sourceVersion: string;
  owner: string;
  declaredSha256: string | null;
  calculatedSha256: string;
  content: string;
  rawContentStored: boolean;
  decision: 'ACCEPT' | 'QUARANTINE';
  classification: string;
  reasons: string[];
  dlp: RagDlpResult;
  trustedSource: boolean;
  status: 'ACTIVE' | 'QUARANTINED';
  ingestionTimestamp: string;
  contradiction?: {
    detected: boolean;
    rule: string;
    candidateValue?: string;
    approvedEvidence?: Array<{ documentId: string; hours: string }>;
  };
  provenance: RagProvenance;
  fileMetadata?: {
    originalFileName: string;
    extension: string;
    declaredContentType: string;
    sizeBytes: number;
    rawSha256: string;
    zeroWidthCharacterCount: number;
    controlCharacterCount: number;
    parser: string;
    parserScope: string;
  } | null;
}

export interface RagStatus {
  acceptedCount: number;
  quarantinedCount: number;
  acceptedEmailCount: number;
  quarantinedEmailCount: number;
  lastDecisionAt: string | null;
  trustedSources: string[];
  trustedEmailDomains: string[];
  tenantIsolation: string;
  authentication: string;
  signaturesRequired: boolean;
  unsafeSimulationEnabled: boolean;
  dlp: string;
  rateLimit: { max: number; windowMs: number };
  telemetry: {
    enabled: boolean;
    endpointConfigured: boolean;
    traceUrlConfigured: boolean;
  };
  accepted: RagDocument[];
  quarantined: RagDocument[];
  acceptedEmails: RagDocument[];
  quarantinedEmails: RagDocument[];
}

export interface RagTraceSpan {
  spanId: string;
  parentSpanId: string | null;
  name: string;
  durationMs: number;
  status: { code: number; message?: string };
  attributes: Record<string, string | number | boolean>;
}

export interface RagTrace {
  traceId: string;
  serviceName: string;
  startedAt: string;
  durationMs: number;
  export: {
    status: 'disabled' | 'exported' | 'failed';
    message?: string;
    httpStatus?: number;
  };
  traceUrl: string | null;
  spans: RagTraceSpan[];
}

export interface RagEvaluator {
  name: string;
  score: number;
  threshold: number;
  passed: boolean;
  explanation: string;
  unsupportedFacts?: string[];
}

export interface RagRetrievedContext {
  resourceId: string;
  documentId: string | null;
  messageId: string | null;
  kind: 'document' | 'email';
  tenantId: string;
  source: string;
  sourceVersion: string;
  decision: string;
  status: string;
  trustedSource: boolean;
  calculatedSha256: string;
  content: string;
  score: number;
}

export interface RagQueryBody {
  answer: string;
  tenantId: string;
  mode: string;
  retrievedContext: RagRetrievedContext[];
  evaluations: {
    groundedness: RagEvaluator;
    contextRelevance: RagEvaluator;
    sourceIntegrity: { passed: boolean; score: number; explanation: string };
    tenantIsolation: { passed: boolean; requestedTenant: string; retrievedTenants: string[] };
  };
  llm: { status: number; correlationId: string; durationMs: number } | null;
  securityConclusion: string;
}

export interface RagIngestionBody {
  decision: 'ACCEPT' | 'QUARANTINE';
  classification: string;
  resourceType: 'document' | 'email';
  resourceId: string;
  documentId?: string;
  messageId?: string;
  tenantId: string;
  reasons: string[];
  provenance: RagProvenance;
  dlp: RagDlpResult;
  contradiction: Record<string, unknown>;
  storedCollection: string;
}

export interface RagScenarioRun {
  scenario: RagScenario;
  result: {
    status: number;
    body: RagQueryBody | RagIngestionBody | Record<string, unknown>;
    trace: RagTrace;
  };
  evaluation: {
    passed: boolean;
    expected: string;
    actual: string;
    detail: string;
  };
  status: RagStatus;
}

export interface RagFileUploadResult {
  httpStatus: number;
  body: RagIngestionBody | Record<string, unknown>;
  trace: RagTrace | null;
  status: RagStatus;
  fileInspection?: Record<string, unknown> | null;
}
