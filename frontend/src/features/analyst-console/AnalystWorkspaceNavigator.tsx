import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, CircleAlert, Download, EyeOff, FileSearch, HardDrive, RefreshCw, Search, ShieldCheck, Target } from "lucide-react";
import { RedPathApiError } from "./api";
import type { AuthMeResponse, CampaignExport, CampaignResponse, ConsoleApi, DetectionRule, EvidenceResponse, InventoryAsset, PcapAnalysisSummary } from "./contracts";
import VirtualizedDataList from "./VirtualizedDataList";
import { maskNetworkIdentity, redactDisplayText, savedFilters, type AnalystDetailView, type TelemetryFreshness, useTelemetryFreshness, useWorkspaceQueryState } from "./workspace-state";
import { formatUtc } from "./model";

import "./analyst-workspace-navigator.css";

type NavigatorProps = {
  api: ConsoleApi;
  session: AuthMeResponse;
  initialEvidence: EvidenceResponse[];
  initialPcapAnalyses: PcapAnalysisSummary[];
  snapshotRefreshedAt: Date;
};

type CatalogState = {
  assets: InventoryAsset[];
  rules: DetectionRule[];
  cases: CampaignResponse[];
  loading: boolean;
  error?: { message: string; status?: number };
};

type WorkspaceRecord = {
  id: string;
  label: string;
  meta: string;
  state: string;
  timestamp?: string;
};

const viewNames: Record<AnalystDetailView, string> = {
  assets: "Assets",
  detections: "Detection rules",
  evidence: "Evidence",
  cases: "Cases",
};
const viewOrder: AnalystDetailView[] = ["assets", "detections", "evidence", "cases"];
const collectionPageSize = 250;
const maxFilteredRecords = 1_000;

function safeError(error: unknown) {
  if (error instanceof RedPathApiError) return { message: error.message, status: error.status };
  return { message: "The authenticated workspace could not load this read-only catalog.", status: undefined };
}

function stateMessage(freshness: TelemetryFreshness) {
  if (freshness === "stale") return "Telemetry is stale. The last authenticated snapshot remains visible, but export previews are paused until a fresh read succeeds.";
  if (freshness === "unavailable") return "Telemetry freshness is unavailable. Read-only lists may be incomplete and export previews are paused.";
  return "Telemetry summary is current within the workspace freshness window.";
}

function stateClass(freshness: TelemetryFreshness) {
  return freshness === "fresh" ? "is-fresh" : freshness === "stale" ? "is-stale" : "is-unavailable";
}

function recordForView(view: AnalystDetailView, catalog: CatalogState, evidence: EvidenceResponse[], pcapAnalyses: PcapAnalysisSummary[]): WorkspaceRecord[] {
  if (view === "assets") return catalog.assets.map((item) => ({ id: item.asset_id, label: redactDisplayText(item.display_name), meta: `${maskNetworkIdentity(item.ip)} · ${item.services.length} services`, state: item.provenance.dry_run ? "dry run" : "policy", timestamp: item.last_seen_at }));
  if (view === "detections") return catalog.rules.map((item) => ({ id: item.rule_id, label: redactDisplayText(item.title), meta: `${item.technique_ids.join(", ")} · ${item.event_sources.length} sources`, state: item.deployment_status, timestamp: undefined }));
  if (view === "evidence") return evidence.map((item) => {
    const analysis = pcapAnalyses.find((candidate) => candidate.evidence_id === item.evidence_id);
    return { id: item.evidence_id, label: redactDisplayText(item.title), meta: `${item.evidence_type} · ${item.technique_id ?? "unmapped"}${analysis ? ` · ${analysis.redacted_fields} redacted fields` : ""}`, state: item.review_status.replace(/_/g, " "), timestamp: item.created_at };
  });
  return catalog.cases.map((item) => ({ id: item.campaign_id, label: redactDisplayText(item.name), meta: `${item.status} · updated ${formatUtc(item.updated_at)}`, state: item.status, timestamp: item.updated_at }));
}

function normalizeSearch(value: string) {
  return value.trim().toLocaleLowerCase();
}

function ExportPreview({ api, caseId, freshness }: { api: ConsoleApi; caseId: string; freshness: TelemetryFreshness }) {
  const [state, setState] = useState<{ kind: "idle" } | { kind: "loading" } | { kind: "ready"; value: CampaignExport } | { kind: "error"; message: string }>({ kind: "idle" });
  const unavailable = freshness !== "fresh";
  const loadPreview = async () => {
    if (unavailable || !api.getCaseExport) return;
    setState({ kind: "loading" });
    try {
      setState({ kind: "ready", value: await api.getCaseExport(caseId) });
    } catch (error) {
      setState({ kind: "error", message: safeError(error).message });
    }
  };

  return <section className="soc-export-preview" aria-labelledby="export-preview-title"><div><span className="soc-card-label">PRIVACY-SAFE EXPORT PREVIEW</span><h3 id="export-preview-title">Review scope before any authorised export.</h3><p>Preview contains only record counts and section names. No download, raw evidence, tenant identifiers, actor identities, or canonical payloads are rendered.</p></div><button className="soc-button" type="button" onClick={() => void loadPreview()} disabled={unavailable || state.kind === "loading"}><Download size={14} /> {state.kind === "loading" ? "Preparing preview…" : "Preview read-only scope"}</button>{unavailable && <small className="soc-export-preview__guard"><EyeOff size={13} /> Preview is paused while telemetry is {freshness}.</small>}{state.kind === "error" && <small className="soc-inline-error" role="alert">{state.message}</small>}{state.kind === "ready" && <div className="soc-export-preview__summary" aria-live="polite"><span>Case summary</span><span>{state.value.evidence.length} evidence records</span><span>{state.value.remediations.length} remediations</span><span>{state.value.governance_history.length} governance events</span><small>Exports remain server-authorized and tenant-scoped; this control does not create, download, or mutate an export.</small></div>}</section>;
}

function DetailPane({ view, selectedId, catalog, evidence, pcapAnalyses, api, freshness }: { view: AnalystDetailView; selectedId: string; catalog: CatalogState; evidence: EvidenceResponse[]; pcapAnalyses: PcapAnalysisSummary[]; api: ConsoleApi; freshness: TelemetryFreshness }) {
  const asset = catalog.assets.find((item) => item.asset_id === selectedId);
  const rule = catalog.rules.find((item) => item.rule_id === selectedId);
  const evidenceItem = evidence.find((item) => item.evidence_id === selectedId);
  const caseItem = catalog.cases.find((item) => item.campaign_id === selectedId);
  if (!selectedId) return <aside className="soc-throughput-detail"><div className="soc-drilldown-empty" role="status"><ShieldCheck size={19} /><div><strong>Select a record</strong><span>Use Arrow keys or select a visible row to inspect bounded, tenant-scoped metadata.</span></div></div></aside>;
  if (view === "assets" && asset) return <aside className="soc-throughput-detail" aria-live="polite"><span className="soc-card-label">ASSET DETAIL</span><h3>{redactDisplayText(asset.display_name)}</h3><dl><div><dt>Network reference</dt><dd>{maskNetworkIdentity(asset.ip)}</dd></div><div><dt>Services</dt><dd>{asset.services.join(", ") || "No services recorded"}</dd></div><div><dt>Observed</dt><dd>{formatUtc(asset.last_seen_at)}</dd></div><div><dt>Safety mode</dt><dd>{asset.provenance.dry_run ? "Dry-run observation" : "Policy controlled"}</dd></div></dl><p><ShieldCheck size={13} /> Actor, tenant, full network identity, and observation hash are withheld.</p></aside>;
  if (view === "detections" && rule) return <aside className="soc-throughput-detail" aria-live="polite"><span className="soc-card-label">DETECTION DETAIL</span><h3>{redactDisplayText(rule.title)}</h3><dl><div><dt>Techniques</dt><dd>{rule.technique_ids.join(", ")}</dd></div><div><dt>Sources</dt><dd>{rule.event_sources.join(", ")}</dd></div><div><dt>Deployment</dt><dd>{rule.deployment_status}</dd></div><div><dt>Bounded conditions</dt><dd>{rule.conditions.length}; condition values are withheld.</dd></div></dl><p><ShieldCheck size={13} /> Rule creation, evaluation, and deployment remain server-authorized.</p></aside>;
  if (view === "evidence" && evidenceItem) {
    const analysis = pcapAnalyses.find((item) => item.evidence_id === evidenceItem.evidence_id);
    return <aside className="soc-throughput-detail" aria-live="polite"><span className="soc-card-label">EVIDENCE DETAIL</span><h3>{redactDisplayText(evidenceItem.title)}</h3><dl><div><dt>Review state</dt><dd>{evidenceItem.review_status.replace(/_/g, " ")}</dd></div><div><dt>Technique</dt><dd>{evidenceItem.technique_id ?? "Unmapped"}</dd></div><div><dt>Collected</dt><dd>{formatUtc(evidenceItem.created_at)}</dd></div>{analysis && <><div><dt>Redaction</dt><dd>{analysis.redaction_mode} · {analysis.redacted_fields} fields withheld</dd></div><div><dt>Summary</dt><dd>{analysis.packet_count} packets · {analysis.flow_count} flows</dd></div></>}</dl><p><EyeOff size={13} /> Canonical payloads, raw PCAP values, full hashes, and reviewer identifiers are not rendered.</p></aside>;
  }
  if (view === "cases" && caseItem) return <aside className="soc-throughput-detail" aria-live="polite"><span className="soc-card-label">CASE DETAIL</span><h3>{redactDisplayText(caseItem.name)}</h3><dl><div><dt>Status</dt><dd>{caseItem.status}</dd></div><div><dt>Updated</dt><dd>{formatUtc(caseItem.updated_at)}</dd></div><div><dt>Scope entries</dt><dd>{caseItem.scope_snapshot.length} bounded references</dd></div></dl><ExportPreview api={api} caseId={caseItem.campaign_id} freshness={freshness} /></aside>;
  return <aside className="soc-throughput-detail"><div className="soc-drilldown-empty" role="status"><ShieldCheck size={19} /><div><strong>Record no longer available</strong><span>The selected identifier is not visible in this tenant-scoped response.</span></div></div></aside>;
}

export default function AnalystWorkspaceNavigator({ api, session, initialEvidence, initialPcapAnalyses, snapshotRefreshedAt }: NavigatorProps) {
  const { query, updateQuery, applySavedFilter } = useWorkspaceQueryState();
  const freshness = useTelemetryFreshness(snapshotRefreshedAt);
  const [catalog, setCatalog] = useState<CatalogState>({ assets: [], rules: [], cases: [], loading: true });
  const readOnlyViewer = session.roles.length > 0 && session.roles.every((role) => role === "viewer");

  const loadCatalog = useCallback(async (signal?: AbortSignal) => {
    setCatalog((current) => ({ ...current, loading: true, error: undefined }));
    try {
      const [assets, rules, cases] = await Promise.all([
        api.getAssets ? api.getAssets({ limit: 100, signal }) : Promise.resolve([]),
        api.getDetectionRules ? api.getDetectionRules({ signal }) : Promise.resolve([]),
        api.getCases ? api.getCases({ signal }) : Promise.resolve([]),
      ]);
      if (!signal?.aborted) setCatalog({ assets, rules, cases, loading: false });
    } catch (error) {
      if (!signal?.aborted) setCatalog((current) => ({ ...current, loading: false, error: safeError(error) }));
    }
  }, [api]);

  useEffect(() => {
    const controller = new AbortController();
    void loadCatalog(controller.signal);
    return () => controller.abort();
  }, [loadCatalog]);

  const allRecords = useMemo(() => recordForView(query.view, catalog, initialEvidence, initialPcapAnalyses), [catalog, initialEvidence, initialPcapAnalyses, query.view]);
  const matching = useMemo(() => {
    const needle = normalizeSearch(query.q);
    const review = query.review;
    return allRecords.filter((record) => (!needle || `${record.id} ${record.label} ${record.meta} ${record.state}`.toLocaleLowerCase().includes(needle)) && (query.view !== "evidence" || review === "all" || record.state === review.replace(/_/g, " "))).slice(0, maxFilteredRecords);
  }, [allRecords, query.q, query.review, query.view]);
  const pageCount = Math.max(1, Math.ceil(matching.length / collectionPageSize));
  const currentPage = Math.min(query.page, pageCount);
  const pageRecords = matching.slice((currentPage - 1) * collectionPageSize, currentPage * collectionPageSize);
  const selectedId = pageRecords.some((record) => record.id === query.selected) ? query.selected : pageRecords[0]?.id ?? "";
  const selectedRecord = pageRecords.find((record) => record.id === selectedId);

  const moveView = (view: AnalystDetailView) => updateQuery({ view, page: 1, selected: "", saved: "all-records" });
  const handleViewKey = (event: React.KeyboardEvent<HTMLButtonElement>, view: AnalystDetailView) => {
    const index = viewOrder.indexOf(view);
    const nextIndex = event.key === "ArrowRight" ? (index + 1) % viewOrder.length : event.key === "ArrowLeft" ? (index - 1 + viewOrder.length) % viewOrder.length : event.key === "Home" ? 0 : event.key === "End" ? viewOrder.length - 1 : -1;
    if (nextIndex < 0) return;
    event.preventDefault();
    const next = viewOrder[nextIndex];
    moveView(next);
    document.getElementById(`throughput-tab-${next}`)?.focus();
  };

  return <section className="soc-throughput" aria-labelledby="throughput-title"><header className="soc-throughput__head"><div><span className="soc-card-label">ANALYST WORKSPACE</span><h2 id="throughput-title">High-throughput, bounded review.</h2><p>Keyboard-first, tenant-scoped records with privacy-safe detail and export-preview controls.</p></div><div className="soc-throughput__status"><div className="soc-throughput__session"><ShieldCheck size={15} /> {readOnlyViewer ? "Viewer · read-only" : `${session.roles.join(" · ")} · read-only`}</div><div className={`soc-freshness ${stateClass(freshness)}`} role="status"><ActivityIcon freshness={freshness} /> {freshness === "fresh" ? "Telemetry current" : freshness === "stale" ? "Telemetry stale" : "Telemetry freshness unavailable"}</div></div></header><p className={`soc-degradation ${stateClass(freshness)}`}><CircleAlert size={14} /> {stateMessage(freshness)}</p><nav className="soc-breadcrumbs" aria-label="Workspace breadcrumb"><span>Analyst workspace</span><ChevronRight size={14} aria-hidden="true" /><span>{viewNames[query.view]}</span>{selectedRecord && <><ChevronRight size={14} aria-hidden="true" /><b>{redactDisplayText(selectedRecord.label)}</b></>}</nav><div className="soc-workspace-controls"><label className="soc-drilldown-search"><Search size={15} /><span className="soc-visually-hidden">Search {viewNames[query.view]}</span><input value={query.q} onChange={(event) => updateQuery({ q: event.target.value, page: 1, selected: "", saved: "all-records" })} placeholder={`Search ${viewNames[query.view].toLowerCase()}`} aria-label={`Search ${viewNames[query.view]}`} /></label><label className="soc-select"><span className="soc-visually-hidden">Saved analyst filter</span><select value={query.saved} onChange={(event) => applySavedFilter(event.target.value)} aria-label="Saved analyst filter">{savedFilters.map((filter) => <option key={filter.id} value={filter.id}>{filter.label}</option>)}</select></label>{query.view === "evidence" && <label className="soc-select"><span className="soc-visually-hidden">Evidence review status</span><select value={query.review} onChange={(event) => updateQuery({ review: event.target.value, page: 1, selected: "", saved: "all-records" })} aria-label="Evidence review status"><option value="all">All review states</option>{Array.from(new Set(initialEvidence.map((item) => item.review_status))).map((status) => <option key={status} value={status}>{status.replace(/_/g, " ")}</option>)}</select></label>}<button className="soc-button" type="button" onClick={() => void loadCatalog()} disabled={catalog.loading}><RefreshCw size={14} /> Refresh read-only</button></div><div className="soc-throughput-tabs" role="tablist" aria-label="High-throughput data views">{viewOrder.map((view) => <button id={`throughput-tab-${view}`} key={view} role="tab" type="button" aria-selected={query.view === view} aria-controls="throughput-panel" tabIndex={query.view === view ? 0 : -1} onClick={() => moveView(view)} onKeyDown={(event) => handleViewKey(event, view)}>{view === "assets" ? <HardDrive size={15} /> : view === "detections" ? <Target size={15} /> : view === "evidence" ? <FileSearch size={15} /> : <ShieldCheck size={15} />}{viewNames[view]}</button>)}</div><div id="throughput-panel" role="tabpanel" tabIndex={0} aria-labelledby={`throughput-tab-${query.view}`} className="soc-throughput__panel">{catalog.loading ? <div className="soc-drilldown-loading" role="status"><RefreshCw size={18} /><span>Loading authorised catalog…</span></div> : catalog.error ? <div className="soc-drilldown-error" role="alert"><CircleAlert size={18} /><div><strong>Catalog unavailable</strong><span>{catalog.error.message}</span><button className="soc-button" type="button" onClick={() => void loadCatalog()}><RefreshCw size={14} /> Retry read-only</button></div></div> : !matching.length ? <div className="soc-drilldown-empty" role="status"><ShieldCheck size={19} /><div><strong>No matching tenant-scoped records</strong><span>Adjust the saved filter, review state, or search query without broadening backend scope.</span></div></div> : <div className="soc-throughput-grid"><section className="soc-throughput-list"><div className="soc-throughput-list__meta"><span>{matching.length}{allRecords.length > maxFilteredRecords ? ` of first ${maxFilteredRecords}` : ""} matching records</span><span>{readOnlyViewer ? "Viewer · read-only" : `${session.roles.join(" · ")} · read-only`}</span></div><VirtualizedDataList ariaLabel={`${viewNames[query.view]} results`} items={pageRecords} activeKey={selectedId} getKey={(item) => item.id} onActiveChange={(item) => updateQuery({ selected: item.id })} renderItem={(item, active) => <div className="soc-throughput-row"><div><strong>{redactDisplayText(item.label)}</strong><small>{redactDisplayText(item.meta)}</small></div><div><span className="soc-safe-pill">{item.state}</span>{item.timestamp && <small>{formatUtc(item.timestamp)}</small>}</div></div>} /><div className="soc-pagination" aria-label="Workspace result pages"><button type="button" aria-label="Previous result page" disabled={currentPage === 1} onClick={() => updateQuery({ page: currentPage - 1, selected: "" })}><ChevronLeft size={15} /></button><span aria-live="polite">Page {currentPage} of {pageCount}</span><button type="button" aria-label="Next result page" disabled={currentPage === pageCount} onClick={() => updateQuery({ page: currentPage + 1, selected: "" })}><ChevronRight size={15} /></button></div></section><DetailPane view={query.view} selectedId={selectedId} catalog={catalog} evidence={initialEvidence} pcapAnalyses={initialPcapAnalyses} api={api} freshness={freshness} /></div>}</div></section>;
}

function ActivityIcon({ freshness }: { freshness: TelemetryFreshness }) {
  return freshness === "fresh" ? <ShieldCheck size={15} /> : <CircleAlert size={15} />;
}
