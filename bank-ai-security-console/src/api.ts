import type {
  HealthStatus,
  InvocationResult,
  Scenario,
  ScenarioRunResponse,
} from './types';

async function parseResponse<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const message = body?.message ?? body?.error ?? `Request failed with HTTP ${response.status}`;
    throw new Error(message);
  }
  return body as T;
}

export async function getHealth(): Promise<HealthStatus> {
  return parseResponse<HealthStatus>(await fetch('/api/health'));
}

export async function getScenarios(): Promise<Scenario[]> {
  const response = await parseResponse<{ scenarios: Scenario[] }>(await fetch('/api/scenarios'));
  return response.scenarios;
}

export async function runScenario(id: string): Promise<ScenarioRunResponse> {
  return parseResponse<ScenarioRunResponse>(
    await fetch(`/api/scenarios/${encodeURIComponent(id)}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

export async function runManualRequest(
  payload: Record<string, unknown>,
  authMode: 'valid' | 'none' | 'invalid',
): Promise<InvocationResult> {
  const response = await parseResponse<{ result: InvocationResult }>(
    await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, authMode }),
    }),
  );
  return response.result;
}

export async function getRagStatus(): Promise<import('./types').RagStatus> {
  return parseResponse<import('./types').RagStatus>(await fetch('/api/rag/status'));
}

export async function getRagScenarios(): Promise<import('./types').RagScenario[]> {
  const response = await parseResponse<{ scenarios: import('./types').RagScenario[] }>(
    await fetch('/api/rag/scenarios'),
  );
  return response.scenarios;
}

export async function runRagScenario(id: string): Promise<import('./types').RagScenarioRun> {
  return parseResponse<import('./types').RagScenarioRun>(
    await fetch(`/api/rag/scenarios/${encodeURIComponent(id)}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

export async function resetRagLab(): Promise<import('./types').RagStatus> {
  return parseResponse<import('./types').RagStatus>(
    await fetch('/api/rag/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

export async function ingestRagDocument(document: Record<string, unknown>): Promise<{
  body: import('./types').RagIngestionBody;
  trace: import('./types').RagTrace;
  status: import('./types').RagStatus;
}> {
  return parseResponse<{
    body: import('./types').RagIngestionBody;
    trace: import('./types').RagTrace;
    status: import('./types').RagStatus;
  }>(
    await fetch('/api/rag/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document }),
    }),
  );
}


export async function ingestRagEmail(email: Record<string, unknown>): Promise<{
  body: import('./types').RagIngestionBody;
  trace: import('./types').RagTrace;
  status: import('./types').RagStatus;
}> {
  return parseResponse<{
    body: import('./types').RagIngestionBody;
    trace: import('./types').RagTrace;
    status: import('./types').RagStatus;
  }>(
    await fetch('/api/rag/ingest-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    }),
  );
}

export async function queryRagLab(input: {
  tenantId: 'tenant-a' | 'tenant-b';
  question: string;
  mode?: 'protected' | 'ungrounded-simulation' | 'unsafe-quarantine-bypass';
}): Promise<{
  body: import('./types').RagQueryBody;
  trace: import('./types').RagTrace;
  status: import('./types').RagStatus;
}> {
  return parseResponse<{
    body: import('./types').RagQueryBody;
    trace: import('./types').RagTrace;
    status: import('./types').RagStatus;
  }>(
    await fetch('/api/rag/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    }),
  );
}


export async function uploadRagFile(input: {
  file: File;
  tenantId: 'tenant-a' | 'tenant-b';
  channel: 'approved-publisher' | 'customer-upload';
  documentId?: string;
}): Promise<import('./types').RagFileUploadResult> {
  const response = await fetch('/api/rag/files', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-File-Name': encodeURIComponent(input.file.name),
      'X-File-Content-Type': input.file.type || 'application/octet-stream',
      'X-Tenant-Id': input.tenantId,
      'X-Upload-Channel': input.channel,
      'X-Document-Id': input.documentId || `FILE-UI-${Date.now()}`,
      'X-Source-Version': new Date().toISOString().slice(0, 10),
    },
    body: input.file,
  });
  const payload = await response.json().catch(() => ({ body: { error: 'INVALID_SERVER_RESPONSE', message: 'The file endpoint did not return JSON.' } }));
  return { ...payload, httpStatus: response.status } as import('./types').RagFileUploadResult;
}
