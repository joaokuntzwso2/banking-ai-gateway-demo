import {
  Braces,
  CheckCircle2,
  KeyRound,
  Link2,
  LoaderCircle,
  Play,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { Scenario, ScenarioRunResponse } from '../types';

interface ScenarioCardProps {
  scenario: Scenario;
  running: boolean;
  lastRun?: ScenarioRunResponse;
  selected: boolean;
  onSelect: () => void;
  onRun: () => void;
}

function assuranceIcon(assurance: string) {
  if (assurance.includes('Authentication')) return KeyRound;
  if (assurance.includes('URL')) return Link2;
  if (assurance.includes('contract')) return Braces;
  if (assurance.includes('Prompt') || assurance.includes('Obfuscation')) return ScanSearch;
  if (assurance.includes('Data-loss')) return ShieldAlert;
  return ShieldCheck;
}

export function ScenarioCard({
  scenario,
  running,
  lastRun,
  selected,
  onSelect,
  onRun,
}: ScenarioCardProps) {
  const Icon = assuranceIcon(scenario.assurance);
  const categoryLabel =
    scenario.category === 'allowed'
      ? 'Expected allow'
      : scenario.category === 'access'
        ? 'Expected deny'
        : 'Expected block';

  return (
    <article
      className={`scenario-card ${selected ? 'selected' : ''}`}
      onClick={onSelect}
      role="button"
      tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') onSelect();
      }}
    >
      <div className="scenario-card-top">
        <div className={`scenario-icon ${scenario.category}`}>
          <Icon size={19} />
        </div>
        <span className={`category-badge ${scenario.category}`}>{categoryLabel}</span>
      </div>

      <div>
        <h3>{scenario.title}</h3>
        <p>{scenario.summary}</p>
      </div>

      <div className="scenario-meta">
        <span>{scenario.assurance}</span>
        <span>HTTP {scenario.expectedStatuses.join(' / ')}</span>
      </div>

      <div className="scenario-policy">{scenario.policy}</div>

      <div className="scenario-actions">
        {lastRun ? (
          <div className={`last-result ${lastRun.evaluation.passed ? 'pass' : 'fail'}`}>
            {lastRun.evaluation.passed ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}
            {lastRun.evaluation.passed ? 'Passed' : 'Review'} · HTTP {lastRun.result.status}
          </div>
        ) : (
          <span className="not-run">Not executed</span>
        )}
        <button
          type="button"
          className="run-button"
          disabled={running}
          onClick={(event) => {
            event.stopPropagation();
            onRun();
          }}
        >
          {running ? <LoaderCircle className="spin" size={16} /> : <Play size={16} fill="currentColor" />}
          {running ? 'Running' : 'Run'}
        </button>
      </div>
    </article>
  );
}
