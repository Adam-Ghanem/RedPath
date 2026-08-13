import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  ClipboardCheck,
  Database,
  FileSearch,
  Gauge,
  ListFilter,
  LockKeyhole,
  Radar,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  TriangleAlert,
} from "lucide-react";
import { consoleApi } from "./api";
import type { ConsoleApi, SnapshotLoadState } from "./contracts";
import { buildAnalystConsoleModel, formatUtc } from "./model";

import "./analyst-console.css";

type ConsolePanel = "priorities" | "detection" | "evidence";

type AnalystConsoleProps = {
  api?: ConsoleApi;
};

const panelLabels: Record<ConsolePanel, string> = {
  priorities: "Remediation priorities",
  detection: "Detection engineering",
  evidence: "Evidence review",
};

function severityClass(value: string) {
  return `soc-severity soc-severity--${value.toLowerCase().replace(/_/g, "-")}`;
}

function EmptyQueue({ title, detail }: { title: string; detail: string }) {
  return <div className="soc-empty"><CheckCircle2 size={18} /><div><strong>{title}</strong><span>{detail}</span></div></div>;
}

function SnapshotError({ message, retry }: { message: string; retry: () => void }) {
  return <main className="soc-page soc-page--centered"><section className="soc-error" role="alert"><ShieldX size={28} /><h1>Console data is unavailable</h1><p>{message}</p><button className="soc-button soc-button--primary" onClick={retry}><RefreshCw size={15} /> Retry read-only refresh</button><a className="soc-link" href="/">Return to the RedPath demo</a></section></main>;
}

export function AnalystConsole({ api = consoleApi }: AnalystConsoleProps) {
  const [state, setState] = useState<SnapshotLoadState>({ kind: "loading" });
  const [activePanel, setActivePanel] = useState<ConsolePanel>("priorities");

  const refresh = async () => {
    setState({ kind: "loading" });
    try {
      const snapshot = await api.getSnapshot();
      setState({ kind: "ready", snapshot, refreshedAt: new Date() });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "An unexpected client error occurred." });
    }
  };

  useEffect(() => { void refresh(); }, []);

  const model = useMemo(() => state.kind === "ready" ? buildAnalystConsoleModel(state.snapshot) : null, [state]);

  if (state.kind === "error") return <SnapshotError message={state.message} retry={() => void refresh()} />;

  if (!model || state.kind !== "ready") {
    return <main className="soc-page soc-page--centered"><section className="soc-loading" aria-live="polite"><Radar className="soc-loading__icon" size={28} /><h1>Building analyst workspace</h1><p>Loading the authorised, read-only SOC summary.</p></section></main>;
  }

  const activeLabel = panelLabels[activePanel];
  const scopeLabel = model.safety.allowedCidrs.length ? model.safety.allowedCidrs.join(" · ") : "No authorised scope recorded";

  return (
    <div className="soc-page">
      <aside className="soc-sidebar" aria-label="Analyst console navigation">
        <a className="soc-brand" href="/" aria-label="Return to RedPath home"><span>R</span><b>REDPATH</b></a>
        <div className="soc-workspace"><span>WORKSPACE</span><strong>Defensive Operations</strong><small>Read-only analyst view</small></div>
        <nav className="soc-nav" aria-label="Console sections">
          <a className="active" href="#overview"><Gauge size={17} /> Overview</a>
          <a href="#queues"><ListFilter size={17} /> Work queues</a>
          <a href="#telemetry"><Activity size={17} /> Validation runs</a>
          <a href="#controls"><LockKeyhole size={17} /> Controls</a>
        </nav>
        <section className="soc-scope-card" aria-label="Authorised scope"><span><ShieldCheck size={15} /> Safety posture</span><b>{model.safety.dryRunDefault ? "Dry-run default" : "Server policy required"}</b><p>{scopeLabel}</p></section>
      </aside>

      <main className="soc-main" id="overview">
        <header className="soc-topbar">
          <div><a className="soc-back" href="/"><ArrowLeft size={14} /> Public demo</a><p className="soc-eyebrow">ANALYST CONSOLE / READ-ONLY</p><h1>Prioritise what matters <em>now.</em></h1></div>
          <div className="soc-topbar__actions"><div className="soc-refresh" aria-live="polite"><span /> Snapshot refreshed {state.refreshedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div><button className="soc-button" onClick={() => void refresh()}><RefreshCw size={15} /> Refresh</button></div>
        </header>

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
              {(Object.keys(panelLabels) as ConsolePanel[]).map((panel) => <button key={panel} className={activePanel === panel ? "active" : ""} onClick={() => setActivePanel(panel)} role="tab" aria-selected={activePanel === panel}>{panelLabels[panel]}</button>)}
            </div>
            {activePanel === "priorities" && <div className="soc-queue-list">{model.remediationQueue.length ? model.remediationQueue.slice(0, 6).map((item) => <article className="soc-queue-row" key={item.remediation_id}><span className={severityClass(item.priority)}>{item.priority}</span><div><strong>{item.finding_title}</strong><small>{item.owner} · {item.state.replace(/_/g, " ")}{item.due_date ? ` · due ${item.due_date}` : ""}</small></div><ChevronRight size={17} /></article>) : <EmptyQueue title="No remediation items" detail="No authorised remediation records are available in this snapshot." />}</div>}
            {activePanel === "detection" && <div className="soc-queue-list">{model.tuningQueue.length ? model.tuningQueue.slice(0, 6).map((item) => <article className="soc-queue-row" key={item.technique_id}><span className={severityClass(item.priority)}>{item.priority}</span><div><strong>{item.technique_id} · {item.rule_intent}</strong><small>{item.gap_count} correlated gaps · {item.event_sources.join(", ") || "Source mapping pending"}</small></div><ChevronRight size={17} /></article>) : <EmptyQueue title="No tuning queue entries" detail="Detection coverage gaps will appear here after validation runs are ingested." />}</div>}
            {activePanel === "evidence" && <div className="soc-queue-list">{model.evidence.pending ? state.snapshot.evidence.filter((item) => item.review_status !== "accepted").slice(0, 6).map((item) => <article className="soc-queue-row" key={item.evidence_id}><span className={severityClass(item.review_status === "rejected" ? "low" : "medium")}>{item.review_status.replace(/_/g, " ")}</span><div><strong>{item.title}</strong><small>{item.evidence_type} · {item.technique_id ?? "No technique link"} · {formatUtc(item.created_at)}</small></div><ChevronRight size={17} /></article>) : <EmptyQueue title="Evidence review complete" detail="All currently available evidence records are accepted." />}</div>}
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
          <article className="soc-panel" id="controls"><div className="soc-panel__head"><div><span className="soc-card-label">CONTROL ASSURANCE</span><h2>Evidence and audit</h2></div><FileSearch size={19} /></div><div className="soc-control-list"><div><span>Audit chain</span><b className={model.evidence.integrityValid ? "healthy" : "attention"}>{model.evidence.integrityValid ? "Verified" : "Review required"}</b></div><div><span>Recorded audit events</span><b>{model.evidence.auditEvents}</b></div><div><span>Accepted evidence</span><b>{model.evidence.reviewed} / {state.snapshot.evidence.length}</b></div><div><span>Default operation mode</span><b>{model.safety.dryRunDefault ? "Dry-run" : "Policy controlled"}</b></div></div></article>
        </section>
      </main>
    </div>
  );
}

export default AnalystConsole;
