import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Banknote,
  Braces,
  DatabaseZap,
  Building2,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  ClipboardCheck,
  Code2,
  FileClock,
  FlaskConical,
  Gauge,
  KeyRound,
  Layers3,
  LayoutDashboard,
  Link2,
  ListChecks,
  LoaderCircle,
  LockKeyhole,
  Menu,
  MessageSquareText,
  Network,
  Play,
  RefreshCw,
  Search,
  Send,
  Server,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Terminal,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { getHealth, getScenarios, runManualRequest, runScenario } from './api';
import { CodeBlock } from './components/CodeBlock';
import { ResultPanel } from './components/ResultPanel';
import { ScenarioCard } from './components/ScenarioCard';
import { RagSecurityLab } from './components/RagSecurityLab';
import type {
  AuditEntry,
  HealthStatus,
  InvocationResult,
  Scenario,
  ScenarioCategory,
  ScenarioRunResponse,
} from './types';

type View = 'overview' | 'scenarios' | 'rag' | 'console' | 'audit';
type Filter = 'all' | ScenarioCategory;

const DEFAULT_MANUAL_PAYLOAD = {
  model: 'gpt-4o-mini',
  temperature: 0,
  messages: [
    {
      role: 'user',
      content: 'Indica brevemente que el pedido DEMO-2001 está siendo revisado.',
    },
  ],
};

const NAV_ITEMS: Array<{ id: View; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'overview', label: 'Control overview', icon: LayoutDashboard },
  { id: 'scenarios', label: 'Scenario laboratory', icon: FlaskConical },
  { id: 'rag', label: 'Protected RAG lab', icon: DatabaseZap },
  { id: 'console', label: 'Live request console', icon: MessageSquareText },
  { id: 'audit', label: 'Audit trail', icon: FileClock },
];

export default function App() {
  const [view, setView] = useState<View>('overview');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenarioRuns, setScenarioRuns] = useState<Record<string, ScenarioRunResponse>>({});
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const [runningIds, setRunningIds] = useState<Set<string>>(new Set());
  const [runAllActive, setRunAllActive] = useState(false);
  const [runAllProgress, setRunAllProgress] = useState({ current: 0, total: 0 });
  const [filter, setFilter] = useState<Filter>('all');
  const [search, setSearch] = useState('');
  const [audit, setAudit] = useState<AuditEntry[]>(loadAudit);
  const [manualPayload, setManualPayload] = useState(JSON.stringify(DEFAULT_MANUAL_PAYLOAD, null, 2));
  const [manualAuthMode, setManualAuthMode] = useState<'valid' | 'none' | 'invalid'>('valid');
  const [manualRunning, setManualRunning] = useState(false);
  const [manualResult, setManualResult] = useState<InvocationResult | null>(null);
  const [manualError, setManualError] = useState<string | null>(null);

  useEffect(() => {
    void initialize();
  }, []);

  useEffect(() => {
    localStorage.setItem('aurelius-ai-security-audit', JSON.stringify(audit.slice(0, 100)));
  }, [audit]);

  async function initialize() {
    try {
      const [healthResponse, scenarioResponse] = await Promise.all([getHealth(), getScenarios()]);
      setHealth(healthResponse);
      setScenarios(scenarioResponse);
      setSelectedScenarioId(scenarioResponse[0]?.id ?? null);
    } catch (error) {
      setHealthError(error instanceof Error ? error.message : String(error));
    }
  }

  async function refreshHealth() {
    setHealthError(null);
    try {
      setHealth(await getHealth());
    } catch (error) {
      setHealthError(error instanceof Error ? error.message : String(error));
    }
  }

  async function executeScenario(scenario: Scenario) {
    setSelectedScenarioId(scenario.id);
    setRunningIds((current) => new Set(current).add(scenario.id));
    try {
      const response = await runScenario(scenario.id);
      setScenarioRuns((current) => ({ ...current, [scenario.id]: response }));
      appendAudit(response);
      return response;
    } catch (error) {
      setHealthError(error instanceof Error ? error.message : String(error));
      return null;
    } finally {
      setRunningIds((current) => {
        const next = new Set(current);
        next.delete(scenario.id);
        return next;
      });
    }
  }

  async function executeAll() {
    if (runAllActive) return;
    setRunAllActive(true);
    setRunAllProgress({ current: 0, total: scenarios.length });
    for (let index = 0; index < scenarios.length; index += 1) {
      await executeScenario(scenarios[index]);
      setRunAllProgress({ current: index + 1, total: scenarios.length });
    }
    setRunAllActive(false);
  }

  function appendAudit(response: ScenarioRunResponse) {
    const check = readCheck(response.result.body);
    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      scenarioId: response.scenario.id,
      title: response.scenario.title,
      category: response.scenario.category,
      passed: response.evaluation.passed,
      status: response.result.status,
      check,
      durationMs: response.result.durationMs,
      timestamp: new Date().toISOString(),
      correlationId: response.result.correlationId,
    };
    setAudit((current) => [entry, ...current].slice(0, 100));
  }

  async function executeManual() {
    setManualError(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(manualPayload) as Record<string, unknown>;
    } catch (error) {
      setManualError(`The request body is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }

    setManualRunning(true);
    try {
      const result = await runManualRequest(parsed, manualAuthMode);
      setManualResult(result);
      const entry: AuditEntry = {
        id: crypto.randomUUID(),
        scenarioId: 'manual',
        title: 'Manual request',
        category: 'manual',
        passed: result.status < 500,
        status: result.status,
        check: readCheck(result.body),
        durationMs: result.durationMs,
        timestamp: new Date().toISOString(),
        correlationId: result.correlationId,
      };
      setAudit((current) => [entry, ...current].slice(0, 100));
    } catch (error) {
      setManualError(error instanceof Error ? error.message : String(error));
    } finally {
      setManualRunning(false);
    }
  }

  function loadScenarioIntoConsole(scenario: Scenario) {
    setManualPayload(JSON.stringify(scenario.payload, null, 2));
    setManualAuthMode(scenario.id === 'negative-missing-api-key' ? 'none' : scenario.id === 'negative-invalid-api-key' ? 'invalid' : 'valid');
    setView('console');
    setMobileOpen(false);
  }

  const selectedRun = selectedScenarioId ? scenarioRuns[selectedScenarioId] : undefined;
  const selectedScenario = scenarios.find((scenario) => scenario.id === selectedScenarioId);

  const filteredScenarios = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();
    return scenarios.filter((scenario) => {
      const filterMatch = filter === 'all' || scenario.category === filter;
      const searchMatch =
        !normalizedSearch ||
        `${scenario.title} ${scenario.summary} ${scenario.policy} ${scenario.assurance}`
          .toLowerCase()
          .includes(normalizedSearch);
      return filterMatch && searchMatch;
    });
  }, [filter, scenarios, search]);

  const metrics = useMemo(() => {
    const completed = Object.values(scenarioRuns);
    const passed = completed.filter((run) => run.evaluation.passed).length;
    const blocked = completed.filter((run) => run.result.status === 422).length;
    const averageLatency = completed.length
      ? Math.round(completed.reduce((sum, run) => sum + run.result.durationMs, 0) / completed.length)
      : 0;
    return {
      completed: completed.length,
      passed,
      blocked,
      passRate: completed.length ? Math.round((passed / completed.length) * 100) : 0,
      averageLatency,
    };
  }, [scenarioRuns]);

  return (
    <div className="app-shell">
      <Sidebar
        view={view}
        onView={(next) => {
          setView(next);
          setMobileOpen(false);
        }}
        mobileOpen={mobileOpen}
        closeMobile={() => setMobileOpen(false)}
        health={health}
      />

      <main className="main-area">
        <TopBar
          view={view}
          onMenu={() => setMobileOpen(true)}
          health={health}
          healthError={healthError}
          onRefresh={() => void refreshHealth()}
        />

        <div className="page-content">
          {view === 'overview' && (
            <Overview
              health={health}
              metrics={metrics}
              scenarios={scenarios}
              scenarioRuns={scenarioRuns}
              onRunAll={() => void executeAll()}
              runAllActive={runAllActive}
              runAllProgress={runAllProgress}
              onOpenScenarios={() => setView('scenarios')}
              recentAudit={audit.slice(0, 5)}
            />
          )}

          {view === 'scenarios' && (
            <ScenarioLaboratory
              scenarios={filteredScenarios}
              allScenarios={scenarios}
              filter={filter}
              setFilter={setFilter}
              search={search}
              setSearch={setSearch}
              selectedScenarioId={selectedScenarioId}
              setSelectedScenarioId={setSelectedScenarioId}
              scenarioRuns={scenarioRuns}
              runningIds={runningIds}
              executeScenario={executeScenario}
              executeAll={executeAll}
              runAllActive={runAllActive}
              runAllProgress={runAllProgress}
              selectedRun={selectedRun}
              selectedScenario={selectedScenario}
              loadScenarioIntoConsole={loadScenarioIntoConsole}
            />
          )}

          {view === 'rag' && <RagSecurityLab />}

          {view === 'console' && (
            <LiveConsole
              payload={manualPayload}
              setPayload={setManualPayload}
              authMode={manualAuthMode}
              setAuthMode={setManualAuthMode}
              running={manualRunning}
              execute={executeManual}
              result={manualResult}
              error={manualError}
              scenarios={scenarios}
              loadScenario={loadScenarioIntoConsole}
            />
          )}

          {view === 'audit' && <AuditTrail audit={audit} clear={() => setAudit([])} />}
        </div>
      </main>
    </div>
  );
}

interface SidebarProps {
  view: View;
  onView: (view: View) => void;
  mobileOpen: boolean;
  closeMobile: () => void;
  health: HealthStatus | null;
}

function Sidebar({ view, onView, mobileOpen, closeMobile, health }: SidebarProps) {
  return (
    <>
      {mobileOpen && <div className="mobile-backdrop" onClick={closeMobile} />}
      <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="brand-row">
          <div className="brand-mark">
            <Building2 size={24} strokeWidth={1.8} />
          </div>
          <div>
            <strong>AURELIUS</strong>
            <span>PRIVATE BANK</span>
          </div>
          <button className="mobile-close" type="button" onClick={closeMobile} aria-label="Close navigation">
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-section-label">AI Security</div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                type="button"
                className={view === item.id ? 'active' : ''}
                onClick={() => onView(item.id)}
              >
                <Icon size={18} />
                <span>{item.label}</span>
                {view === item.id && <ChevronRight size={15} className="nav-chevron" />}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-spacer" />

        <div className="environment-card">
          <div className="environment-title">
            <Server size={17} />
            Local environment
          </div>
          <div className="environment-line">
            <span className={`status-dot ${health?.gatewayReachable ? 'online' : 'offline'}`} />
            <span>{health?.gatewayReachable ? 'Gateway reachable' : 'Gateway unavailable'}</span>
          </div>
          <div className="environment-line">
            <span className={`status-dot ${health?.apiKeyConfigured ? 'online' : 'offline'}`} />
            <span>{health?.apiKeyConfigured ? 'API key loaded' : 'API key missing'}</span>
          </div>
          <small>{health?.endpoint ?? 'Waiting for configuration'}</small>
        </div>

        <div className="sidebar-footer">
          <ShieldCheck size={17} />
          <div>
            <strong>Security profile</strong>
            <span>Banking controls active</span>
          </div>
        </div>
      </aside>
    </>
  );
}

interface TopBarProps {
  view: View;
  onMenu: () => void;
  health: HealthStatus | null;
  healthError: string | null;
  onRefresh: () => void;
}

function TopBar({ view, onMenu, health, healthError, onRefresh }: TopBarProps) {
  const title = NAV_ITEMS.find((item) => item.id === view)?.label ?? 'AI Security';
  return (
    <header className="topbar">
      <button className="mobile-menu" type="button" onClick={onMenu} aria-label="Open navigation">
        <Menu size={21} />
      </button>
      <div>
        <span className="breadcrumb">Digital Banking / AI Controls</span>
        <h1>{title}</h1>
      </div>
      <div className="topbar-actions">
        {healthError && (
          <div className="topbar-alert" title={healthError}>
            <AlertTriangle size={16} />
            Configuration issue
          </div>
        )}
        <div className={`gateway-pill ${health?.status === 'ready' ? 'ready' : 'degraded'}`}>
          <CircleDot size={14} />
          {health?.status === 'ready' ? 'Gateway ready' : 'Gateway degraded'}
        </div>
        <button className="icon-button" type="button" onClick={onRefresh} title="Refresh gateway status">
          <RefreshCw size={17} />
        </button>
        <div className="user-avatar">JK</div>
      </div>
    </header>
  );
}

interface OverviewProps {
  health: HealthStatus | null;
  metrics: { completed: number; passed: number; blocked: number; passRate: number; averageLatency: number };
  scenarios: Scenario[];
  scenarioRuns: Record<string, ScenarioRunResponse>;
  onRunAll: () => void;
  runAllActive: boolean;
  runAllProgress: { current: number; total: number };
  onOpenScenarios: () => void;
  recentAudit: AuditEntry[];
}

function Overview({
  health,
  metrics,
  scenarios,
  scenarioRuns,
  onRunAll,
  runAllActive,
  runAllProgress,
  onOpenScenarios,
  recentAudit,
}: OverviewProps) {
  const blockedCoverage = scenarios.filter((scenario) => scenario.category === 'blocked').length;
  const accessCoverage = scenarios.filter((scenario) => scenario.category === 'access').length;
  const allowedCoverage = scenarios.filter((scenario) => scenario.category === 'allowed').length;

  return (
    <div className="overview-stack">
      <section className="hero-panel">
        <div className="hero-copy">
          <div className="hero-kicker">
            <BadgeCheck size={16} />
            Controlled banking AI environment
          </div>
          <h2>Validate every AI request before it reaches your customers.</h2>
          <p>
            Exercise authentication, prompt-injection defense, content controls, URL safety, and structured-output contracts through the live WSO2 AI Gateway.
          </p>
          <div className="hero-actions">
            <button className="primary-button" type="button" onClick={onRunAll} disabled={runAllActive}>
              {runAllActive ? <LoaderCircle className="spin" size={17} /> : <Play size={17} fill="currentColor" />}
              {runAllActive ? `Running ${runAllProgress.current}/${runAllProgress.total}` : 'Run complete control suite'}
            </button>
            <button className="secondary-button" type="button" onClick={onOpenScenarios}>
              Review scenarios
              <ChevronRight size={17} />
            </button>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="bank-core">
            <div className="bank-core-ring outer" />
            <div className="bank-core-ring inner" />
            <div className="bank-core-icon">
              <LockKeyhole size={34} />
            </div>
            <span className="orbit-node node-one"><ShieldCheck size={15} /></span>
            <span className="orbit-node node-two"><Braces size={15} /></span>
            <span className="orbit-node node-three"><Link2 size={15} /></span>
          </div>
        </div>
      </section>

      <section className="metric-grid">
        <MetricCard icon={Activity} label="Gateway status" value={health?.gatewayReachable ? 'Operational' : 'Unavailable'} detail={health?.endpoint ?? 'Awaiting connection'} tone={health?.gatewayReachable ? 'success' : 'danger'} />
        <MetricCard icon={Layers3} label="Active policies" value={String(health?.policies.length ?? 8)} detail="Granular controls in enforced order" tone="blue" />
        <MetricCard icon={ClipboardCheck} label="Suite pass rate" value={metrics.completed ? `${metrics.passRate}%` : 'Not run'} detail={`${metrics.passed} of ${metrics.completed} completed checks`} tone="gold" />
        <MetricCard icon={Gauge} label="Average latency" value={metrics.completed ? `${metrics.averageLatency} ms` : '—'} detail="Measured end-to-end through gateway" tone="neutral" />
      </section>

      <div className="overview-grid">
        <section className="panel policy-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Enforcement architecture</span>
              <h2>Live policy chain</h2>
            </div>
            <span className="panel-chip">{health?.policies.length ?? 8} controls</span>
          </div>
          <div className="policy-chain">
            {(health?.policies ?? []).map((policy, index) => (
              <div className="policy-step" key={policy}>
                <div className="policy-index">{String(index + 1).padStart(2, '0')}</div>
                <div className="policy-step-copy">
                  <strong>{policy}</strong>
                  <span>{policyDescription(policy)}</span>
                </div>
                <CheckCircle2 size={18} className="policy-check" />
              </div>
            ))}
          </div>
        </section>

        <section className="panel coverage-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Control assurance</span>
              <h2>Scenario coverage</h2>
            </div>
            <span className="panel-chip">{scenarios.length} cases</span>
          </div>
          <CoverageRow icon={CheckCircle2} label="Approved banking journeys" value={allowedCoverage} total={scenarios.length} tone="allowed" />
          <CoverageRow icon={ShieldX} label="Threat interventions" value={blockedCoverage} total={scenarios.length} tone="blocked" />
          <CoverageRow icon={KeyRound} label="Access-control denials" value={accessCoverage} total={scenarios.length} tone="access" />
          <div className="coverage-summary">
            <div>
              <strong>{metrics.blocked}</strong>
              <span>Interventions observed</span>
            </div>
            <div>
              <strong>{Object.keys(scenarioRuns).length}</strong>
              <span>Scenarios executed</span>
            </div>
          </div>
        </section>
      </div>

      <section className="panel demo-workspace-panel">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">Customer demonstration workspace</span>
            <h2>Architecture and evidence windows</h2>
          </div>
          <span className="panel-chip">UI-led flow</span>
        </div>
        <div className="demo-workspace-grid">
          <div><Building2 size={18} /><span>AI Workspace</span><strong>Provider guardrails</strong></div>
          <div><Layers3 size={18} /><span>Secure proxy</span><strong>Policies & ordering</strong></div>
          <div><Network size={18} /><span>MCP proxies</span><strong>Tool boundaries</strong></div>
          <div><Activity size={18} /><span>Agent Manager</span><strong>Traces & evaluators</strong></div>
          <div><MessageSquareText size={18} /><span>Bank console</span><strong>Positive & negative tests</strong></div>
          <div><Server size={18} /><span>Gateway runtime</span><strong>Health & correlation IDs</strong></div>
        </div>
      </section>

      <section className="panel recent-panel">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">Operational evidence</span>
            <h2>Recent decisions</h2>
          </div>
        </div>
        {recentAudit.length ? (
          <div className="compact-audit">
            {recentAudit.map((entry) => (
              <div className="compact-audit-row" key={entry.id}>
                <div className={`audit-status-icon ${entry.passed ? 'pass' : 'fail'}`}>
                  {entry.passed ? <CheckCircle2 size={17} /> : <AlertTriangle size={17} />}
                </div>
                <div className="compact-audit-copy">
                  <strong>{entry.title}</strong>
                  <span>{entry.check ?? 'No guardrail intervention'} · {formatTime(entry.timestamp)}</span>
                </div>
                <span className={`http-mini ${entry.status >= 200 && entry.status < 300 ? 'ok' : entry.status === 401 ? 'auth' : 'blocked'}`}>HTTP {entry.status}</span>
                <span className="audit-duration">{entry.durationMs} ms</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState icon={ListChecks} title="No decisions recorded" text="Run the suite to populate auditable control evidence." />
        )}
      </section>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone }: { icon: typeof Activity; label: string; value: string; detail: string; tone: string }) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${tone}`}><Icon size={20} /></div>
      <div className="metric-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </div>
  );
}

function CoverageRow({ icon: Icon, label, value, total, tone }: { icon: typeof CheckCircle2; label: string; value: number; total: number; tone: string }) {
  const percentage = total ? Math.round((value / total) * 100) : 0;
  return (
    <div className="coverage-row">
      <div className={`coverage-icon ${tone}`}><Icon size={18} /></div>
      <div className="coverage-main">
        <div><span>{label}</span><strong>{value}</strong></div>
        <div className="progress-track"><div className={`progress-fill ${tone}`} style={{ width: `${percentage}%` }} /></div>
      </div>
    </div>
  );
}

interface ScenarioLaboratoryProps {
  scenarios: Scenario[];
  allScenarios: Scenario[];
  filter: Filter;
  setFilter: (filter: Filter) => void;
  search: string;
  setSearch: (search: string) => void;
  selectedScenarioId: string | null;
  setSelectedScenarioId: (id: string) => void;
  scenarioRuns: Record<string, ScenarioRunResponse>;
  runningIds: Set<string>;
  executeScenario: (scenario: Scenario) => Promise<ScenarioRunResponse | null>;
  executeAll: () => Promise<void>;
  runAllActive: boolean;
  runAllProgress: { current: number; total: number };
  selectedRun?: ScenarioRunResponse;
  selectedScenario?: Scenario;
  loadScenarioIntoConsole: (scenario: Scenario) => void;
}

function ScenarioLaboratory({
  scenarios,
  allScenarios,
  filter,
  setFilter,
  search,
  setSearch,
  selectedScenarioId,
  setSelectedScenarioId,
  scenarioRuns,
  runningIds,
  executeScenario,
  executeAll,
  runAllActive,
  runAllProgress,
  selectedRun,
  selectedScenario,
  loadScenarioIntoConsole,
}: ScenarioLaboratoryProps) {
  return (
    <div className="laboratory-layout">
      <section className="laboratory-main">
        <div className="page-intro-row">
          <div>
            <span className="eyebrow">Live security verification</span>
            <h2>Banking AI control scenarios</h2>
            <p>Run approved journeys, access-control denials, and adversarial cases through the active gateway.</p>
          </div>
          <button className="primary-button" type="button" disabled={runAllActive} onClick={() => void executeAll()}>
            {runAllActive ? <LoaderCircle className="spin" size={17} /> : <Play size={17} fill="currentColor" />}
            {runAllActive ? `${runAllProgress.current}/${runAllProgress.total} completed` : 'Run all scenarios'}
          </button>
        </div>

        <div className="scenario-toolbar">
          <div className="filter-tabs">
            {([
              ['all', 'All cases'],
              ['allowed', 'Approved'],
              ['blocked', 'Threats'],
              ['access', 'Access'],
            ] as Array<[Filter, string]>).map(([id, label]) => (
              <button key={id} type="button" className={filter === id ? 'active' : ''} onClick={() => setFilter(id)}>
                {label}
                <span>{id === 'all' ? allScenarios.length : allScenarios.filter((item) => item.category === id).length}</span>
              </button>
            ))}
          </div>
          <label className="search-field">
            <Search size={17} />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search policy, risk, or scenario" />
          </label>
        </div>

        <div className="scenario-grid">
          {scenarios.map((scenario) => (
            <ScenarioCard
              key={scenario.id}
              scenario={scenario}
              running={runningIds.has(scenario.id)}
              lastRun={scenarioRuns[scenario.id]}
              selected={selectedScenarioId === scenario.id}
              onSelect={() => setSelectedScenarioId(scenario.id)}
              onRun={() => void executeScenario(scenario)}
            />
          ))}
        </div>
      </section>

      <aside className="laboratory-result-column">
        {selectedScenario && (
          <div className="selected-scenario-tools">
            <div>
              <span>Selected scenario</span>
              <strong>{selectedScenario.title}</strong>
            </div>
            <button type="button" onClick={() => loadScenarioIntoConsole(selectedScenario)}>
              <Code2 size={16} />
              Open in console
            </button>
          </div>
        )}
        <ResultPanel
          result={selectedRun?.result ?? null}
          evaluation={selectedRun?.evaluation}
          scenario={selectedRun?.scenario ?? selectedScenario}
        />
      </aside>
    </div>
  );
}

interface LiveConsoleProps {
  payload: string;
  setPayload: (payload: string) => void;
  authMode: 'valid' | 'none' | 'invalid';
  setAuthMode: (mode: 'valid' | 'none' | 'invalid') => void;
  running: boolean;
  execute: () => Promise<void>;
  result: InvocationResult | null;
  error: string | null;
  scenarios: Scenario[];
  loadScenario: (scenario: Scenario) => void;
}

function LiveConsole({ payload, setPayload, authMode, setAuthMode, running, execute, result, error, scenarios, loadScenario }: LiveConsoleProps) {
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const formatted = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(payload), null, 2);
    } catch {
      return payload;
    }
  }, [payload]);

  return (
    <div className="console-page">
      <div className="page-intro-row">
        <div>
          <span className="eyebrow">Controlled experimentation</span>
          <h2>Live request console</h2>
          <p>Send a custom OpenAI-compatible payload through the same banking policy chain. The API key remains server-side.</p>
        </div>
        <div className="security-note"><LockKeyhole size={16} /> API key redacted from browser</div>
      </div>

      <div className="console-grid">
        <section className="panel request-composer">
          <div className="panel-heading compact">
            <div>
              <span className="eyebrow">Request builder</span>
              <h2>Chat Completions payload</h2>
            </div>
            <button className="text-button" type="button" onClick={() => setPayload(JSON.stringify(DEFAULT_MANUAL_PAYLOAD, null, 2))}>
              <RefreshCw size={15} /> Reset
            </button>
          </div>

          <div className="console-fields">
            <label>
              <span>Scenario template</span>
              <select
                value={selectedTemplate}
                onChange={(event) => {
                  const id = event.target.value;
                  setSelectedTemplate(id);
                  const scenario = scenarios.find((candidate) => candidate.id === id);
                  if (scenario) loadScenario(scenario);
                }}
              >
                <option value="">Choose a predefined banking case</option>
                {scenarios.map((scenario) => <option key={scenario.id} value={scenario.id}>{scenario.title}</option>)}
              </select>
            </label>

            <label>
              <span>Inbound authentication</span>
              <div className="segmented-control">
                {([
                  ['valid', 'Valid key'],
                  ['none', 'No key'],
                  ['invalid', 'Invalid key'],
                ] as const).map(([mode, label]) => (
                  <button key={mode} type="button" className={authMode === mode ? 'active' : ''} onClick={() => setAuthMode(mode)}>{label}</button>
                ))}
              </div>
            </label>
          </div>

          <div className="json-editor-shell">
            <div className="editor-toolbar">
              <span><Terminal size={15} /> Request JSON</span>
              <button className="icon-text-button" type="button" onClick={() => setPayload(formatted)}><Sparkles size={15} /> Format</button>
            </div>
            <textarea value={payload} onChange={(event) => setPayload(event.target.value)} spellCheck={false} aria-label="Request JSON" />
          </div>

          {error && <div className="form-error"><AlertTriangle size={17} />{error}</div>}

          <button className="primary-button wide" type="button" onClick={() => void execute()} disabled={running}>
            {running ? <LoaderCircle className="spin" size={18} /> : <Send size={18} />}
            {running ? 'Sending through gateway' : 'Send secured request'}
          </button>
        </section>

        <ResultPanel result={result} emptyTitle="Send a request to view the decision" />
      </div>
    </div>
  );
}

function AuditTrail({ audit, clear }: { audit: AuditEntry[]; clear: () => void }) {
  return (
    <div className="audit-page">
      <div className="page-intro-row">
        <div>
          <span className="eyebrow">Evidence and traceability</span>
          <h2>AI security audit trail</h2>
          <p>Review recent decisions recorded by this browser session. No API keys or provider credentials are stored.</p>
        </div>
        <button className="secondary-button" type="button" onClick={clear} disabled={!audit.length}>Clear audit</button>
      </div>

      <section className="panel audit-table-panel">
        {audit.length ? (
          <div className="table-scroll">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Decision</th>
                  <th>Scenario</th>
                  <th>Policy check</th>
                  <th>HTTP</th>
                  <th>Latency</th>
                  <th>Timestamp</th>
                  <th>Correlation ID</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((entry) => (
                  <tr key={entry.id}>
                    <td><span className={`decision-pill ${entry.passed ? 'pass' : 'fail'}`}>{entry.passed ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}{entry.passed ? 'Confirmed' : 'Review'}</span></td>
                    <td><strong>{entry.title}</strong><small>{entry.category}</small></td>
                    <td>{entry.check ?? 'No intervention'}</td>
                    <td><span className={`http-mini ${entry.status >= 200 && entry.status < 300 ? 'ok' : entry.status === 401 ? 'auth' : 'blocked'}`}>{entry.status}</span></td>
                    <td>{entry.durationMs} ms</td>
                    <td>{formatDateTime(entry.timestamp)}</td>
                    <td><code>{entry.correlationId.slice(0, 24)}…</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={FileClock} title="Audit trail is empty" text="Executed scenarios and manual requests will be recorded here." />
        )}
      </section>
    </div>
  );
}

function EmptyState({ icon: Icon, title, text }: { icon: typeof FileClock; title: string; text: string }) {
  return (
    <div className="empty-state">
      <div><Icon size={25} /></div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}

function policyDescription(policy: string) {
  const descriptions: Record<string, string> = {
    'api-key-auth': 'Inbound API key enforcement',
    'canonicalize-and-classify': 'Direct, encoded, and Unicode injection detection',
    'custom-jailbreak-intent-guardrail': 'Paraphrase, persona-switch, and authority-bypass classification',
    'custom-request-regex-guardrail': 'Configurable request pattern controls',
    'custom-request-dlp-redaction': 'PII, PCI, IBAN, and secret redaction before model access',
    'custom-harmful-content-guardrail': 'Self-harm and violence category enforcement',
    'custom-high-impact-decision-guardrail': 'Protected-attribute blocking and mandatory human review',
    'custom-sensitive-context-guardrail': 'Employee health and family context protection',
    'custom-reliance-guardrail': 'Evidence, uncertainty, and human-review discipline',
    'custom-prompt-decorator': 'Enterprise banking system instructions',
    'custom-request-block-finalizer': 'Quarantined request decision finalization',
    'custom-response-regex-guardrail': 'Canary, secret, and leakage marker prevention',
    'custom-response-url-guardrail': 'Public URL, SSRF, DNS, and reachability validation',
    'custom-response-json-schema-guardrail': 'Conditional structured-output contract',
  };
  return descriptions[policy] ?? 'Active gateway control';
}

function readCheck(body: unknown): string | null {
  if (!body || typeof body !== 'object') return null;
  const message = (body as { message?: unknown }).message;
  if (!message || typeof message !== 'object') return null;
  const check = (message as { check?: unknown }).check;
  return typeof check === 'string' ? check : null;
}

function loadAudit(): AuditEntry[] {
  try {
    const value = localStorage.getItem('aurelius-ai-security-audit');
    return value ? (JSON.parse(value) as AuditEntry[]) : [];
  } catch {
    return [];
  }
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(value));
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value));
}
