import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Database,
  FileSearch,
  Gauge,
  ListFilter,
  LockKeyhole,
  LogOut,
  Radar,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  TriangleAlert,
} from "lucide-react";
import { consoleApi, RedPathApiError } from "./api";
import type { AuthMeResponse, ConsoleApi, SnapshotLoadState } from "./contracts";
import { buildAnalystConsoleModel, formatUtc } from "./model";

import "./analyst-console.css";

type ConsolePanel = "priorities" | "detection" | "evidence";

type AnalystConsoleProps = {
  api?: ConsoleApi;
  onExit?: () => void;
};

type SessionLoadState =
  | { kind: "loading" }
  | { kind: "auth-required"; message: string }
  | { kind: "ready"; session: AuthMeResponse };

const panelLabels: Record<ConsolePanel, string> = {
  priorities: "Remediation priorities",
  detection: "Detection engineering",
  evidence: "Evidence review",
};

const panelOrder: ConsolePanel[] = ["priorities", "detection", "evidence"];

function severityClass(value: string) {
  return `soc-severity soc-severity--${value.toLowerCase().replace(/_/g, "-")}`;
}

function EmptyQueue({ title, detail }: { title: string; detail: string }) {
  return <div className="soc-empty" role="status" aria-live="polite"><CheckCircle2 size={18} /><div><strong>{title}</strong><span>{detail}</span></div></div>;
}

export function SnapshotError({ message, status, retry, onExit }: { message: string; status?: number; retry: () => void; onExit: () => void }) {
  return <main className="soc-page soc-page--centered"><section className="soc-error" role="alert"><ShieldX size={28} /><h1>Console data is unavailable</h1><p>{message}</p>{status === 429 && <small>Wait briefly before retrying; the server rate limit remains in force.</small>}<div className="soc-error__actions"><button className="soc-button soc-button--primary" onClick={retry}><RefreshCw size={15} /> Retry read-only refresh</button><button className="soc-link soc-link--button" onClick={onExit}>Return to RedPath home</button></div></section></main>;
}

export function SessionRequired({ api, message, retry, onExit }: { api: ConsoleApi; message: string; retry: () => void; onExit: () => void }) {
  const [tenantSlug, setTenantSlug] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!api.login) {
      setError("This workspace is not configured with an authenticated sign-in contract.");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      await api.login({ tenant_slug: tenantSlug.trim(), username: username.trim(), password });
      setPassword("");
      retry();
    } catch (cause) {
      setError(cause instanceof RedPathApiError ? cause.message : "Authentication could not be completed.");
    } finally {
      setSubmitting(false);
    }
  };

  return <main className="soc-page soc-page--centered"><section className="soc-auth-panel" aria-labelledby="soc-auth-title"><div className="soc-auth-panel__icon"><LockKeyhole size={25} /></div><span className="soc-card-label">AUTHENTICATED WORKSPACE</span><h1 id="soc-auth-title">Sign in to the analyst console</h1><p>{message} Actor identity, tenant scope, roles, and audit attribution are supplied by the server after authentication.</p><form onSubmit={submit}><label>Tenant slug<input required value={tenantSlug} onChange={(event) => setTenantSlug(event.target.value)} autoComplete="organization" /></label><label>Username<input required value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label><label>Password<input required type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>{error && <p className="soc-auth-error" role="alert">{error}</p>}<div className="soc-error__actions"><button className="soc-button soc-button--primary" type="submit" disabled={submitting}>{submitting ? "Signing in…" : "Sign in read-only"}</button><button className="soc-link soc-link--button" type="button" onClick={onExit}>Return to RedPath home</button></div></form></section></main>;
}

export function SessionIdentity({ session, onLogout }: { session: AuthMeResponse; onLogout: () => void }) {
  return <section className="soc-session" aria-label="Authenticated analyst session"><div className="soc-session__identity"><span className="soc-session__icon"><ShieldCheck size={15} /></span><div><strong>{session.username}</strong><small>{session.tenant_slug} · {session.roles.join(" · ")}</small></div></div><button className="soc-session__logout" type="button" onClick={onLogout}><LogOut size={14} /> Sign out</button></section>;
}

export function AnalystConsole({ api = consoleApi, onExit = () => { window.location.hash = "top"; } }: AnalystConsoleProps) {
  const [state, setState] = useState<SnapshotLoadState>({ kind: "loading" });
  const [sessionState, setSessionState] = useState<SessionLoadState>({ kind: "loading" });
  const [activePanel, setActivePanel] = useState<ConsolePanel>("priorities");
  const [activeSection, setActiveSection] = useState("overview");

  const loadWorkspace = useCallback(async (signal?: AbortSignal) => {
    if (!api.getSession) {
      setSessionState({ kind: "auth-required", message: "An authenticated session is required to view this workspace." });
      setState({ kind: "auth-required", message: "An authenticated session is required to view this workspace." });
      return;
    }

    setSessionState({ kind: "loading" });
    setState({ kind: "loading" });
    try {
      const session = await api.getSession();
      if (signal?.aborted) return;
      setSessionState({ kind: "ready", session });
      const snapshot = await api.getSnapshot({ signal });
      if (signal?.aborted) return;
      setState({ kind: "ready", snapshot, session, refreshedAt: new Date() });
    } catch (cause) {
      if (signal?.aborted) return;
      const status = cause instanceof RedPathApiError ? cause.status : undefined;
      const message = cause instanceof RedPathApiError ? cause.message : "The authenticated RedPath API is unavailable.";
      if (status === 401) {
        setSessionState({ kind: "auth-required", message });
        setState({ kind: "auth-required", message });
      } else {
        setState({ kind: "error", message, status });
      }
    }
  }, [api]);

  const refresh = useCallback(() => { void loadWorkspace(); }, [loadWorkspace]);

  useEffect(() => {
    const controller = new AbortController();
    void loadWorkspace(controller.signal);
    return () => controller.abort();
  }, [loadWorkspace]);

  const model = useMemo(() => state.kind === "ready" ? buildAnalystConsoleModel(state.snapshot) : null, [state]);

  if (state.kind === "error") return <SnapshotError message={state.message} status={state.status} retry={refresh} onExit={onExit} />;

  if (sessionState.kind === "auth-required" || state.kind === "auth-required") {
    const message = sessionState.kind === "auth-required" ? sessionState.message : state.kind === "auth-required" ? state.message : "Authentication is required to view this workspace.";
    return <SessionRequired api={api} message={message} retry={refresh} onExit={onExit} />;
  }

  if (sessionState.kind === "loading" || state.kind === "loading" || !model) {
    return <main className="soc-page soc-page--centered"><section className="soc-loading" role="status" aria-live="polite"><Radar className="soc-loading__icon" size={28} /><h1>Building analyst workspace</h1><p>Loading the authenticated, read-only SOC summary.</p></section></main>;
  }

  const activeLabel = panelLabels[activePanel];
  const scopeLabel = model.safety.allowedCidrs.length ? model.safety.allowedCidrs.join(" · ") : "No authorised scope recorded";
  const session = state.session;

  const handlePanelKeyDown = (event: KeyboardEvent<HTMLButtonElement>, current: ConsolePanel) => {
    const index = panelOrder.indexOf(current);
    const nextIndex = event.key === "ArrowRight" ? (index + 1) % panelOrder.length : event.key === "ArrowLeft" ? (index - 1 + panelOrder.length) % panelOrder.length : event.key === "Home" ? 0 : event.key === "End" ? panelOrder.length - 1 : -1;
    if (nextIndex < 0) return;
    event.preventDefault();
    const nextPanel = panelOrder[nextIndex];
    setActivePanel(nextPanel);
    document.getElementById(`panel-tab-${nextPanel}`)?.focus();
  };

  const logout = () => {
    api.logout?.();
    onExit();
  };

  return <div className="soc-page">
    <aside className="soc-sidebar" aria-label="Analyst console navigation">
      <button className="soc-brand soc-brand--button" type="button" onClick={onExit} aria-label="Return to RedPath home"><span>R</span><b>REDPATH</b></button>
      <div className="soc-workspace"><span>WORKSPACE</span><strong>Defensive Operations</strong><small>Read-only analyst view</small></div>
      <nav className="soc-nav" aria-label="Console sections">
        <a className={activeSection === "overview" ? "active" : ""} href="#overview" aria-current={activeSection === "overview" ? "page" : undefined} onClick={() => setActiveSection("overview")}><Gauge size={17} /> Overview</a>
        <a className={activeSection === "queues" ? "active" : ""} href="#queues" aria-current={activeSection === "queues" ? "page" : undefined} onClick={() => setActiveSection("queues")}><ListFilter size={17} /> Work queues</a>
        <a className={activeSection === "telemetry" ? "active" : ""} href="#telemetry" aria-current={activeSection === "telemetry" ? "page" : undefined} onClick={() => setActiveSection("telemetry")}><Activity size={17} /> Validation runs</a>
        <a className={activeSection === "controls" ? "active" : ""} href="#controls" aria-current={activeSection === "controls" ? "page" : undefined} onClick={() => setActiveSection("controls")}><LockKeyhole size={17} /> Controls</a>
      </nav>
      <section className="soc-scope-card" aria-label="Authorised scope"><span><ShieldCheck size={15} /> Safety posture</span><b>{model.safety.dryRunDefault ? "Dry-run default" : "Server policy required"}</b><p>{scopeLabel}</p></section>
    </aside>

    <main className="soc-main" id="overview">
      <header className="soc-topbar">
        <div><button className="soc-back" type="button" onClick={onExit}><ArrowLeft size={14} /> RedPath home</button><p className="soc-eyebrow">ANALYST CONSOLE / READ-ONLY</p><h1>Prioritise what matters <em>now.</em></h1></div>
        <div className="soc-topbar__actions"><div className="soc-refresh" aria-live="polite"><span /> Snapshot refreshed {state.refreshedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div><button className="soc-button" onClick={refresh}><RefreshCw size={15} /> Refresh</button></div>
      </header>

      <SessionIdentity session={session} onLogout={logout} />
      <section className="soc-kpis" aria-label="Security posture overview">
        <article className="soc-risk-card"><div><span className="soc-card-label">EXPOSURE RISK</span><strong>{model.posture.riskScore}<small>/100</small></strong><p>Weighted from the current authorised assessment portfolio.</p></div><div className={`soc-risk-ring ${severityClass(model.posture.riskLabel)}`} style={{ "--risk-score": `${model.posture.riskScore * 3.6}deg` } as React.CSSProperties}><span>{model.posture.riskLabel}</span></div></article>
        <article className="soc-kpi"><span className="soc-card-label">EFFECTIVE COVERAGE</span><strong>{model.posture.effectiveCoveragePercent}<small>%</small></strong><div className="soc-progress"><i style={{ width: `${model.posture.effectiveCoveragePercent}%` }} /></div><p>{model.posture.openGaps} open technique gaps</p></article>
        <article className="soc-kpi"><span className="soc-card-label">CRITICAL FINDINGS</span><strong>{model.posture.openCriticalFindings}</strong><p><TriangleAlert size={14} /> Analyst triage required</p></article>
        <article className="soc-kpi"><span className="soc-card-label">EVIDENCE ASSURANCE</span><strong>{model.evidence.pending}</strong><p>{model.evidence.integrityValid ? <><CheckCircle2 size={14} /> Audit chain verified</> : <><CircleAlert size={14} /> Audit verification needs review</>}</p></article>
      </section>

      <section className="soc-workspace-grid" id="queues">
        <article className="soc-panel soc-panel--queue">
          <div className="soc-panel__head"><div><span className="soc-card-label">ACTION BOARD</span><h2>{activeLabel}</h2></div><span className="soc-count">{activePanel === "priorities" ? model.remediationQueue.length : activePanel === "detection" ? model.tuningQueue.length : model.evidence.pending}</span></div>
          <div className="soc-tabs" role="tablist" aria-label="Analyst queues">
            {panelOrder.map((panel) => <button id={`panel-tab-${panel}`} key={panel} className={activePanel === panel ? "active" : ""} onClick={() => setActivePanel(panel)} onKeyDown={(event) => handlePanelKeyDown(event, panel)} role="tab" aria-selected={activePanel === panel} aria-controls="panel-content" tabIndex={activePanel === panel ? 0 : -1}>{panelLabels[panel]}</button>)}
          </div>
          <div className="soc-queue-list" id="panel-content" role="tabpanel" tabIndex={0} aria-labelledby={`panel-tab-${activePanel}`}>
            {activePanel === "priorities" && (model.remediationQueue.length ? model.remediationQueue.slice(0, 6).map((item) => <article className="soc-queue-row" key={item.remediation_id}><span className={severityClass(item.priority)}>{item.priority}</span><div><strong>{item.finding_title}</strong><small>{item.owner} · {item.state.replace(/_/g, " ")}{item.due_date ? ` · due ${item.due_date}` : ""}</small></div><ChevronRight size={17} aria-hidden="true" /></article>) : <EmptyQueue title="No remediation items" detail="No authorised remediation records are available in this snapshot." />)}
            {activePanel === "detection" && (model.tuningQueue.length ? model.tuningQueue.slice(0, 6).map((item) => <article className="soc-queue-row" key={item.technique_id}><span className={severityClass(item.priority)}>{item.priority}</span><div><strong>{item.technique_id} · {item.rule_intent}</strong><small>{item.gap_count} correlated gaps · {item.event_sources.join(", ") || "Source mapping pending"}</small></div><ChevronRight size={17} aria-hidden="true" /></article>) : <EmptyQueue title="No tuning queue entries" detail="Detection coverage gaps will appear here after validation runs are ingested." />)}
            {activePanel === "evidence" && (model.evidence.pending ? state.snapshot.evidence.filter((item) => item.review_status !== "accepted").slice(0, 6).map((item) => <article className="soc-queue-row" key={item.evidence_id}><span className={severityClass(item.review_status === "rejected" ? "low" : "medium")}>{item.review_status.replace(/_/g, " ")}</span><div><strong>{item.title}</strong><small>{item.evidence_type} · {item.technique_id ?? "No technique link"} · {formatUtc(item.created_at)}</small></div><ChevronRight size={17} aria-hidden="true" /></article>) : <EmptyQueue title="Evidence review complete" detail="All currently available evidence records are accepted." />)}
          </div>
          <p className="soc-panel__foot"><LockKeyhole size={13} /> Queue interactions are intentionally non-mutating. Record updates stay in authorised case workflows.</p>
        </article>

        <article className="soc-panel soc-panel--coverage">
          <div className="soc-panel__head"><div><span className="soc-card-label">DETECTION POSTURE</span><h2>Coverage, not volume.</h2></div><Radar size={20} /></div>
          <div className="soc-coverage-stat"><strong>{model.posture.coveragePercent}%</strong><span>expected techniques detected</span></div>
          <div className="soc-coverage-bars"><div><span>Observed coverage</span><b>{model.posture.coveragePercent}%</b><i><em style={{ width: `${model.posture.coveragePercent}%` }} /></i></div><div><span>Effective coverage</span><b>{model.posture.effectiveCoveragePercent}%</b><i><em className="effective" style={{ width: `${model.posture.effectiveCoveragePercent}%` }} /></i></div></div>
          <div className="soc-signal-callout"><SlidersHorizontal size={18} /><p><b>{model.tuningQueue.length} rule-tuning item{model.tuningQueue.length === 1 ? "" : "s"}</b> are awaiting detection engineering review.</p></div>
        </article>
      </section>

      <section className="soc-lower-grid" id="telemetry">
        <article className="soc-panel"><div className="soc-panel__head"><div><span className="soc-card-label">RECENT VALIDATION</span><h2>Assessment runs</h2></div><Database size={19} /></div>{model.recentRuns.length ? <div className="soc-run-list">{model.recentRuns.slice(0, 4).map((run) => <article key={run.run_id}><div><strong>{run.scenario_id}</strong><small>{run.summary}</small></div><div><span className={run.dry_run ? "soc-run-state" : "soc-run-state soc-run-state--live"}>{run.dry_run ? "DRY RUN" : "REVIEW"}</span><small>{formatUtc(run.created_at)}</small></div><b>{run.coverage_percent}%</b></article>)}</div> : <EmptyQueue title="No validation runs yet" detail="Authorised dry-run assessments will appear here when the backend records them." />}</article>
        <article className="soc-panel" id="controls"><div className="soc-panel__head"><div><span className="soc-card-label">CONTROL ASSURANCE</span><h2>Evidence and audit</h2></div><FileSearch size={19} /></div><div className="soc-control-list"><div><span>Audit chain</span><b className={model.evidence.integrityValid ? "healthy" : "attention"}>{model.evidence.integrityValid ? "Verified" : "Review required"}</b></div><div><span>Recorded audit events</span><b>{model.evidence.auditEvents}</b></div><div><span>Accepted evidence</span><b>{model.evidence.reviewed} / {state.snapshot.evidence.length}</b></div><div><span>Default operation mode</span><b>{model.safety.dryRunDefault ? "Dry-run" : "Policy controlled"}</b></div><div><span>AI explanation policy</span><b className="attention">Verify before acting</b></div></div></article>
      </section>
    </main>
  </div>;
}

export default AnalystConsole;
