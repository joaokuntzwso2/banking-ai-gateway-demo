import {
  CheckCircle2,
  CircleX,
  Clock3,
  FileJson2,
  Fingerprint,
  Route,
  ShieldAlert,
  SquareTerminal,
} from 'lucide-react';
import { useState } from 'react';
import type { InvocationResult, ScenarioEvaluation, Scenario } from '../types';
import { CodeBlock } from './CodeBlock';

interface ResultPanelProps {
  result: InvocationResult | null;
  evaluation?: ScenarioEvaluation;
  scenario?: Scenario;
  emptyTitle?: string;
}

type Tab = 'summary' | 'request' | 'response' | 'curl';

export function ResultPanel({ result, evaluation, scenario, emptyTitle }: ResultPanelProps) {
  const [tab, setTab] = useState<Tab>('summary');

  if (!result) {
    return (
      <section className="result-panel empty-result">
        <div className="empty-result-icon">
          <Route size={28} />
        </div>
        <h3>{emptyTitle ?? 'Select and run a scenario'}</h3>
        <p>The request, policy decision, gateway response, and reproducible cURL will appear here.</p>
      </section>
    );
  }

  const passed = evaluation?.passed;
  const statusTone =
    result.category === 'allowed'
      ? 'allowed'
      : result.category === 'unauthorized'
        ? 'unauthorized'
        : result.category === 'blocked'
          ? 'blocked'
          : 'error';

  const statusLabel =
    result.category === 'allowed'
      ? 'Request allowed'
      : result.category === 'unauthorized'
        ? 'Access denied'
        : result.category === 'blocked'
          ? 'Guardrail intervened'
          : 'Gateway error';

  const check =
    typeof result.body === 'object' && result.body !== null
      ? ((result.body as { message?: { check?: string } }).message?.check ?? 'No intervention')
      : 'No intervention';

  return (
    <section className="result-panel">
      <div className={`result-hero ${statusTone}`}>
        <div className="result-hero-icon">
          {result.category === 'allowed' ? <CheckCircle2 size={26} /> : <ShieldAlert size={26} />}
        </div>
        <div>
          <span className="eyebrow">Latest decision</span>
          <h2>{statusLabel}</h2>
          <p>{scenario?.title ?? 'Manual gateway request'}</p>
        </div>
        <div className="http-status">HTTP {result.status}</div>
      </div>

      <div className="result-tabs" role="tablist">
        {(['summary', 'request', 'response', 'curl'] as Tab[]).map((candidate) => (
          <button
            type="button"
            role="tab"
            aria-selected={tab === candidate}
            className={tab === candidate ? 'active' : ''}
            key={candidate}
            onClick={() => setTab(candidate)}
          >
            {candidate === 'summary' && <Fingerprint size={15} />}
            {candidate === 'request' && <FileJson2 size={15} />}
            {candidate === 'response' && <Route size={15} />}
            {candidate === 'curl' && <SquareTerminal size={15} />}
            {candidate}
          </button>
        ))}
      </div>

      <div className="result-content">
        {tab === 'summary' && (
          <>
            {evaluation && (
              <div className={`verification-banner ${passed ? 'pass' : 'fail'}`}>
                {passed ? <CheckCircle2 size={19} /> : <CircleX size={19} />}
                <div>
                  <strong>{passed ? 'Expected control behavior confirmed' : 'Result differs from expectation'}</strong>
                  <span>
                    Expected HTTP {scenario?.expectedStatuses.join(' / ')}
                    {scenario?.expectedCheck ? ` and check “${scenario.expectedCheck}”` : ''}.
                  </span>
                </div>
              </div>
            )}

            <div className="result-metrics">
              <div>
                <Clock3 size={17} />
                <span>Latency</span>
                <strong>{result.durationMs.toLocaleString()} ms</strong>
              </div>
              <div>
                <Route size={17} />
                <span>Control decision</span>
                <strong>{check}</strong>
              </div>
              <div>
                <Fingerprint size={17} />
                <span>Correlation ID</span>
                <strong title={result.correlationId}>{shorten(result.correlationId, 24)}</strong>
              </div>
            </div>

            {evaluation?.detail && <div className="assessment-note">{evaluation.detail}</div>}

            <div className="decision-grid">
              <div>
                <span>Expected</span>
                <strong>{scenario ? `HTTP ${scenario.expectedStatuses.join(' / ')}` : 'Manual execution'}</strong>
              </div>
              <div>
                <span>Actual</span>
                <strong>HTTP {result.status}</strong>
              </div>
              <div>
                <span>Policy owner</span>
                <strong>{scenario?.policy ?? check}</strong>
              </div>
              <div>
                <span>Security outcome</span>
                <strong>{statusLabel}</strong>
              </div>
            </div>
          </>
        )}

        {tab === 'request' && (
          <CodeBlock value={JSON.stringify(result.request, null, 2)} label="Gateway request (key redacted)" />
        )}

        {tab === 'response' && (
          <CodeBlock value={JSON.stringify(result.body, null, 2)} label={`Gateway response · HTTP ${result.status}`} />
        )}

        {tab === 'curl' && <CodeBlock value={result.curl} label="Reproducible cURL" />}
      </div>
    </section>
  );
}

function shorten(value: string, max: number) {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}
