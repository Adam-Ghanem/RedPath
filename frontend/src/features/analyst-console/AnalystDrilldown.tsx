import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  FileSearch,
  Filter,
  HardDrive,
  ListChecks,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
} from "lucide-react";
import { RedPathApiError } from "./api";
import type {
  AuthMeResponse,
  CampaignExport,
  CampaignResponse,
  ConsoleApi,
  DetectionRule,
  EvidenceManifest,
  EvidenceResponse,
  InventoryAsset,
  PcapAnalysisSummary,
  PcapEvidenceView,
} from "./contracts";
import { formatUtc } from "./model";

import "./analyst-drilldown.css";

type DetailView = "assets" | "detections" | "evidence" | "cases";
type LoadState<T> =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; value: T }
  | { kind: "error"; message: string; status?: number };

type AnalystDrilldownProps = {
  api: ConsoleApi;
  session: AuthMeResponse;
  initialEvidence: EvidenceResponse[];
  initialPcapAnalyses: PcapAnalysisSummary[];
};

const viewLabels: Record<DetailView, string> = {
  assets: "Assets",
  detections: "Detection rules",
  evidence: "Evidence",
  cases: "Cases",
};
const viewOrder: DetailView[] = ["assets", "detections", "evidence", "cases"];
const pageSize = 6;

function messageFor(error: unknown) {
  if (error instanceof RedPathApiError) return { message: error.message, status: error.status };
  return { message: "The authenticated detail view could not be loaded.", status: undefined };
}

function hashPreview(value: string) {
  return value.length > 12 ? `${value.slice(0, 12)}…` : value;
}

function severityClass(value: string) {
  return `soc-severity soc-severity--${value.toLowerCase().replace(/_/g, "-")}`;
}

function EmptyDetail({ title, detail }: { title: string; detail: string }) {
  return <div className="soc-drilldown-empty" role="status" aria-live="polite"><ShieldCheck size={19} /><div><strong>{title}</strong><span>{detail}</span></div></div>;
}

function ErrorDetail({ state, retry }: { state: Extract<LoadState<unknown>, { kind: "error" }>; retry: () => void }) {
  return <div className="soc-drilldown-error" role="alert"><CircleAlert size={18} /><div><strong>Detail data unavailable</strong><span>{state.message}</span>{state.status === 429 && <small>Wait briefly before retrying; the server limit remains in force.</small>}<button className="soc-button" type="button" onClick={retry}><RefreshCw size={14} /> Retry read-only</button></div></div>;
}

function LoadingDetail({ label }: { label: string }) {
  return <div className="soc-drilldown-loading" role="status" aria-live="polite"><Activity size={18} /><span>Loading authorised {label.toLowerCase()}…</span></div>;
}

function Pagination({ page, pageCount, onPage }: { page: number; pageCount: number; onPage: (next: number) => void }) {
  if (pageCount <= 1) return null;
  return <nav className="soc-pagination" aria-label="Detail view pagination"><button type="button" aria-label="Previous page" disabled={page === 1} onClick={() => onPage(page - 1)}><ChevronLeft size={15} /></button><span aria-live="polite">Page {page} of {pageCount}</span><button type="button" aria-label="Next page" disabled={page === pageCount} onClick={() => onPage(page + 1)}><ChevronRight size={15} /></button></nav>;
}

function SearchBar({ value, onChange, label }: { value: string; onChange: (next: string) => void; label: string }) {
  return <label className="soc-drilldown-search"><Search size={15} /><span className="soc-visually-hidden">{label}</span><input value={value} onChange={(event) => onChange(event.target.value)} placeholder={label} aria-label={label} /></label>;
}

function AssetView({ state, retry }: { state: LoadState<InventoryAsset[]>; retry: () => void }) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const assets = state.kind === "ready" ? state.value : [];
  const filtered = useMemo(() => assets.filter((asset) => `${asset.asset_id} ${asset.display_name} ${asset.ip} ${asset.hostname ?? ""} ${asset.services.join(" ")}`.toLowerCase().includes(search.toLowerCase())), [assets, search]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);
  const selected = assets.find((asset) => asset.asset_id === selectedId) ?? visible[0];

  useEffect(() => { setPage(1); }, [search]);
  if (state.kind === "loading") return <LoadingDetail label="assets" />;
  if (state.kind === "error") return <ErrorDetail state={state} retry={retry} />;
  if (state.kind !== "ready" || !assets.length) return <EmptyDetail title="No authorised assets" detail="No tenant-scoped inventory records are available for this workspace." />;

  return <div className="soc-detail-layout"><section className="soc-detail-list" aria-label="Asset inventory"><div className="soc-detail-toolbar"><SearchBar value={search} onChange={setSearch} label="Search assets, hosts, IPs, or services" /><span className="soc-result-count">{filtered.length} records</span></div>{visible.length ? <div className="soc-data-table-wrap"><table className="soc-data-table"><caption className="soc-visually-hidden">Tenant-scoped asset inventory</caption><thead><tr><th scope="col">Asset</th><th scope="col">Network identity</th><th scope="col">Services</th><th scope="col">Mode</th></tr></thead><tbody>{visible.map((asset) => <tr key={asset.asset_id} className={asset.asset_id === selected?.asset_id ? "is-selected" : ""}><td><button type="button" onClick={() => setSelectedId(asset.asset_id)} aria-pressed={asset.asset_id === selected?.asset_id}><strong>{asset.display_name}</strong><small>{asset.asset_id}</small></button></td><td><span>{asset.ip}</span><small>{asset.hostname ?? "Hostname unavailable"}</small></td><td><span>{asset.services.slice(0, 3).join(", ") || "Service inventory pending"}</span><small>{asset.ports.length} observed ports</small></td><td><span className="soc-safe-pill">{asset.provenance.dry_run ? "DRY RUN" : "POLICY"}</span></td></tr>)}</tbody></table></div> : <EmptyDetail title="No matching assets" detail="Try a broader asset, host, IP, or service search." />}<Pagination page={page} pageCount={pageCount} onPage={setPage} /></section><AssetDetail asset={selected} /></div>;
}

function AssetDetail({ asset }: { asset?: InventoryAsset }) {
  if (!asset) return <aside className="soc-detail-card"><EmptyDetail title="Select an asset" detail="Choose an authorised inventory row to inspect its bounded observation metadata." /></aside>;
  return <aside className="soc-detail-card" aria-live="polite"><div className="soc-detail-card__head"><div><span className="soc-card-label">ASSET DETAIL</span><h3>{asset.display_name}</h3></div><HardDrive size={19} /></div><dl className="soc-detail-facts"><div><dt>Asset ID</dt><dd>{asset.asset_id}</dd></div><div><dt>Network identity</dt><dd>{asset.ip}{asset.hostname ? ` · ${asset.hostname}` : ""}</dd></div><div><dt>Services</dt><dd>{asset.services.join(", ") || "No services recorded"}</dd></div><div><dt>Ports</dt><dd>{asset.ports.length ? asset.ports.join(", ") : "No ports recorded"}</dd></div><div><dt>Provenance</dt><dd>{asset.provenance.source} · {formatUtc(asset.provenance.observed_at)}</dd></div></dl><p className="soc-detail-note"><ShieldCheck size={14} /> Observation provenance is server-supplied. Actor, tenant, and raw observation hashes are not rendered.</p></aside>;
}

function DetectionView({ state, retry }: { state: LoadState<DetectionRule[]>; retry: () => void }) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const rules = state.kind === "ready" ? state.value : [];
  const filtered = useMemo(() => rules.filter((rule) => `${rule.rule_id} ${rule.title} ${rule.technique_ids.join(" ")} ${rule.event_sources.join(" ")}`.toLowerCase().includes(search.toLowerCase())), [rules, search]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);
  const selected = rules.find((rule) => rule.rule_id === selectedId) ?? visible[0];
  useEffect(() => { setPage(1); }, [search]);
  if (state.kind === "loading") return <LoadingDetail label="detection rules" />;
  if (state.kind === "error") return <ErrorDetail state={state} retry={retry} />;
  if (state.kind !== "ready" || !rules.length) return <EmptyDetail title="No authorised detection rules" detail="No tenant-scoped detection rule catalog entries are available." />;

  return <div className="soc-detail-layout"><section className="soc-detail-list" aria-label="Detection rules"><div className="soc-detail-toolbar"><SearchBar value={search} onChange={setSearch} label="Search rules, techniques, or sources" /><span className="soc-result-count">{filtered.length} rules</span></div>{visible.length ? <div className="soc-data-table-wrap"><table className="soc-data-table"><caption className="soc-visually-hidden">Read-only detection rule catalog</caption><thead><tr><th scope="col">Rule</th><th scope="col">Techniques</th><th scope="col">Sources</th><th scope="col">State</th></tr></thead><tbody>{visible.map((rule) => <tr key={rule.rule_id} className={rule.rule_id === selected?.rule_id ? "is-selected" : ""}><td><button type="button" onClick={() => setSelectedId(rule.rule_id)} aria-pressed={rule.rule_id === selected?.rule_id}><strong>{rule.title}</strong><small>{rule.rule_id} · v{rule.version}</small></button></td><td><span>{rule.technique_ids.join(", ")}</span><small className={severityClass(rule.severity)}>{rule.severity}</small></td><td><span>{rule.event_sources.join(", ")}</span><small>{rule.window_seconds}s window</small></td><td><span className="soc-safe-pill">{rule.deployment_status}</span><small>{rule.requires_approval ? "Approval required" : "No approval flag"}</small></td></tr>)}</tbody></table></div> : <EmptyDetail title="No matching detection rules" detail="Try a broader rule, technique, or event-source search." />}<Pagination page={page} pageCount={pageCount} onPage={setPage} /></section><DetectionDetail rule={selected} /></div>;
}

function DetectionDetail({ rule }: { rule?: DetectionRule }) {
  if (!rule) return <aside className="soc-detail-card"><EmptyDetail title="Select a detection rule" detail="Choose a read-only rule to inspect coverage intent and bounded conditions." /></aside>;
  return <aside className="soc-detail-card" aria-live="polite"><div className="soc-detail-card__head"><div><span className="soc-card-label">DETECTION DETAIL</span><h3>{rule.title}</h3></div><Target size={19} /></div><p className="soc-detail-copy">{rule.description}</p><dl className="soc-detail-facts"><div><dt>Techniques</dt><dd>{rule.technique_ids.join(", ")}</dd></div><div><dt>Match mode</dt><dd>{rule.match_mode} · {rule.window_seconds}s window</dd></div><div><dt>Event sources</dt><dd>{rule.event_sources.join(", ")}</dd></div><div><dt>Conditions</dt><dd>{rule.conditions.length} bounded condition{rule.conditions.length === 1 ? "" : "s"}; values withheld from the UI.</dd></div><div><dt>Deployment</dt><dd>{rule.deployment_status} · {rule.requires_approval ? "approval required" : "no approval flag"}</dd></div></dl><p className="soc-detail-note"><ListChecks size={14} /> This view is read-only. Rule registration, evaluation, and deployment remain server-authorized workflows.</p></aside>;
}

function EvidenceView({ evidence, pcapAnalyses, api }: { evidence: EvidenceResponse[]; pcapAnalyses: PcapAnalysisSummary[]; api: ConsoleApi }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [manifest, setManifest] = useState<LoadState<EvidenceManifest>>({ kind: "idle" });
  const [pcap, setPcap] = useState<LoadState<PcapEvidenceView>>({ kind: "idle" });
  const filtered = useMemo(() => evidence.filter((item) => (filter === "all" || item.review_status === filter) && `${item.evidence_id} ${item.title} ${item.evidence_type} ${item.technique_id ?? ""}`.toLowerCase().includes(search.toLowerCase())), [evidence, filter, search]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);
  const selected = evidence.find((item) => item.evidence_id === selectedId) ?? visible[0];
  const selectedPcap = selected ? pcapAnalyses.find((item) => item.evidence_id === selected.evidence_id) : undefined;

  useEffect(() => { setPage(1); }, [search, filter]);
  const selectEvidence = useCallback(async (item: EvidenceResponse) => {
    setSelectedId(item.evidence_id);
    const pcapForEvidence = pcapAnalyses.find((candidate) => candidate.evidence_id === item.evidence_id);
    setManifest({ kind: "loading" });
    setPcap({ kind: "idle" });
    try {
      if (!api.getEvidenceManifest) throw new Error("Evidence manifest contract is pending.");
      setManifest({ kind: "ready", value: await api.getEvidenceManifest(item.evidence_id) });
      if (pcapForEvidence && api.getPcapEvidenceView) {
        try {
          setPcap({ kind: "ready", value: await api.getPcapEvidenceView(item.evidence_id) });
        } catch (error) {
          const detail = messageFor(error);
          if (detail.status !== 404) setPcap({ kind: "error", ...detail });
        }
      }
    } catch (error) {
      setManifest({ kind: "error", ...messageFor(error) });
    }
  }, [api, pcapAnalyses]);

  if (!evidence.length) return <EmptyDetail title="No authorised evidence" detail="No tenant-scoped evidence records are available for this workspace." />;
  return <div className="soc-detail-layout"><section className="soc-detail-list" aria-label="Evidence ledger"><div className="soc-detail-toolbar"><SearchBar value={search} onChange={setSearch} label="Search evidence, source, or technique" /><label className="soc-select"><Filter size={14} /><span className="soc-visually-hidden">Filter evidence review state</span><select value={filter} onChange={(event) => setFilter(event.target.value)} aria-label="Filter evidence review state"><option value="all">All review states</option>{Array.from(new Set(evidence.map((item) => item.review_status))).map((status) => <option key={status} value={status}>{status.replace(/_/g, " ")}</option>)}</select></label><span className="soc-result-count">{filtered.length} records</span></div>{visible.length ? <div className="soc-data-table-wrap"><table className="soc-data-table"><caption className="soc-visually-hidden">Redacted evidence ledger</caption><thead><tr><th scope="col">Evidence</th><th scope="col">Source</th><th scope="col">Review</th><th scope="col">Collected</th></tr></thead><tbody>{visible.map((item) => <tr key={item.evidence_id} className={item.evidence_id === selected?.evidence_id ? "is-selected" : ""}><td><button type="button" onClick={() => void selectEvidence(item)} aria-pressed={item.evidence_id === selected?.evidence_id}><strong>{item.title}</strong><small>{item.evidence_type} · {hashPreview(item.sha256)}</small></button></td><td><span>{item.source}</span><small>{item.technique_id ?? "No technique link"}</small></td><td><span className="soc-safe-pill">{item.review_status.replace(/_/g, " ")}</span><small>{item.reviewer ? "Server-reviewed" : "Awaiting review"}</small></td><td>{formatUtc(item.created_at)}</td></tr>)}</tbody></table></div> : <EmptyDetail title="No matching evidence" detail="Try a broader evidence, source, or technique search." />}<Pagination page={page} pageCount={pageCount} onPage={setPage} /></section><EvidenceDetail evidence={selected} pcap={selectedPcap} manifest={manifest} pcapView={pcap} /></div>;
}

function EvidenceDetail({ evidence, pcap, manifest, pcapView }: { evidence?: EvidenceResponse; pcap?: PcapAnalysisSummary; manifest: LoadState<EvidenceManifest>; pcapView: LoadState<PcapEvidenceView> }) {
  if (!evidence) return <aside className="soc-detail-card"><EmptyDetail title="Select evidence" detail="Choose a redacted evidence record to inspect its bounded provenance." /></aside>;
  return <aside className="soc-detail-card" aria-live="polite"><div className="soc-detail-card__head"><div><span className="soc-card-label">EVIDENCE DETAIL</span><h3>{evidence.title}</h3></div><FileSearch size={19} /></div><dl className="soc-detail-facts"><div><dt>Type</dt><dd>{evidence.evidence_type}</dd></div><div><dt>Source</dt><dd>{evidence.source}</dd></div><div><dt>Review</dt><dd>{evidence.review_status}{evidence.reviewer ? " · server-reviewed" : ""}</dd></div><div><dt>Manifest</dt><dd>{manifest.kind === "loading" ? "Loading manifest…" : manifest.kind === "ready" ? `${hashPreview(manifest.value.manifest_sha256)} · ${formatUtc(manifest.value.generated_at)}` : manifest.kind === "error" ? manifest.message : "Select to load"}</dd></div></dl>{pcap && <div className="soc-pcap-summary"><span className="soc-card-label">REDACTED PCAP SUMMARY</span><div><b>{pcap.packet_count}</b><small>packets</small><b>{pcap.flow_count}</b><small>flows</small><b>{pcap.dns_count}</b><small>DNS records</small></div><p>{pcap.capture_format} · {pcap.redaction_mode} · {pcap.redacted_fields} fields redacted</p>{pcapView.kind === "error" && <small className="soc-inline-error">{pcapView.message}</small>}</div>}<p className="soc-detail-note"><ShieldCheck size={14} /> Raw canonical payloads, tenant identifiers, actor names, IP/DNS values, and secret-bearing fields are withheld from the UI.</p></aside>;
}

function CaseView({ api }: { api: ConsoleApi }) {
  const [state, setState] = useState<LoadState<CampaignResponse[]>>({ kind: "loading" });
  const [detail, setDetail] = useState<LoadState<CampaignExport>>({ kind: "idle" });
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const loadCases = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      if (!api.getCases) throw new Error("Case list contract is pending.");
      setState({ kind: "ready", value: await api.getCases() });
    } catch (error) {
      setState({ kind: "error", ...messageFor(error) });
    }
  }, [api]);
  useEffect(() => { void loadCases(); }, [loadCases]);
  const cases = state.kind === "ready" ? state.value : [];
  const filtered = useMemo(() => cases.filter((item) => `${item.campaign_id} ${item.name} ${item.owner} ${item.status}`.toLowerCase().includes(search.toLowerCase())), [cases, search]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);
  const selected = cases.find((item) => item.campaign_id === selectedId) ?? visible[0];
  useEffect(() => { setPage(1); }, [search]);
  const selectCase = async (item: CampaignResponse) => {
    setSelectedId(item.campaign_id);
    setDetail({ kind: "loading" });
    try {
      if (!api.getCaseExport) throw new Error("Case detail contract is pending.");
      setDetail({ kind: "ready", value: await api.getCaseExport(item.campaign_id) });
    } catch (error) {
      setDetail({ kind: "error", ...messageFor(error) });
    }
  };

  if (state.kind === "loading") return <LoadingDetail label="cases" />;
  if (state.kind === "error") return <ErrorDetail state={state} retry={() => void loadCases()} />;
  if (state.kind !== "ready" || !cases.length) return <EmptyDetail title="No authorised cases" detail="No tenant-scoped case records are visible for this authenticated role." />;
  return <div className="soc-detail-layout"><section className="soc-detail-list" aria-label="Case register"><div className="soc-detail-toolbar"><SearchBar value={search} onChange={setSearch} label="Search cases, owners, or status" /><span className="soc-result-count">{filtered.length} cases</span></div>{visible.length ? <div className="soc-data-table-wrap"><table className="soc-data-table"><caption className="soc-visually-hidden">Tenant-scoped case register</caption><thead><tr><th scope="col">Case</th><th scope="col">Owner</th><th scope="col">Status</th><th scope="col">Updated</th></tr></thead><tbody>{visible.map((item) => <tr key={item.campaign_id} className={item.campaign_id === selected?.campaign_id ? "is-selected" : ""}><td><button type="button" onClick={() => void selectCase(item)} aria-pressed={item.campaign_id === selected?.campaign_id}><strong>{item.name}</strong><small>{item.campaign_id}</small></button></td><td>{item.owner}</td><td><span className="soc-safe-pill">{item.status}</span></td><td>{formatUtc(item.updated_at)}</td></tr>)}</tbody></table></div> : <EmptyDetail title="No matching cases" detail="Try a broader case, owner, or status search." />}<Pagination page={page} pageCount={pageCount} onPage={setPage} /></section><CaseDetail detail={detail} selected={selected} retry={() => { if (selected) void selectCase(selected); }} /></div>;
}

function CaseDetail({ detail, selected, retry }: { detail: LoadState<CampaignExport>; selected?: CampaignResponse; retry: () => void }) {
  if (!selected) return <aside className="soc-detail-card"><EmptyDetail title="Select a case" detail="Choose a case to load its tenant-scoped evidence and governance summary." /></aside>;
  if (detail.kind === "loading") return <aside className="soc-detail-card"><LoadingDetail label="case detail" /></aside>;
  if (detail.kind === "error") return <aside className="soc-detail-card"><ErrorDetail state={detail} retry={retry} /></aside>;
  if (detail.kind !== "ready") return <aside className="soc-detail-card"><p className="soc-detail-copy">Select the case to load its server-authorized detail.</p></aside>;
  const value = detail.value;
  return <aside className="soc-detail-card" aria-live="polite"><div className="soc-detail-card__head"><div><span className="soc-card-label">CASE DETAIL</span><h3>{value.campaign.name}</h3></div><FileSearch size={19} /></div><p className="soc-detail-copy">{value.campaign.objective}</p><dl className="soc-detail-facts"><div><dt>Status</dt><dd>{value.campaign.status}</dd></div><div><dt>Owner</dt><dd>{value.campaign.owner}</dd></div><div><dt>Evidence</dt><dd>{value.evidence.length} records</dd></div><div><dt>Remediation</dt><dd>{value.remediations.length} records</dd></div><div><dt>Governance</dt><dd>{value.governance_history.length} events</dd></div></dl><div className="soc-case-timeline"><span className="soc-card-label">GOVERNANCE HISTORY</span>{value.governance_history.slice(0, 4).map((event) => <div key={event.event_id}><b>{event.event_type}</b><small>{event.summary} · {formatUtc(event.created_at)}</small></div>)}{!value.governance_history.length && <span>No governance events available.</span>}</div><p className="soc-detail-note"><ShieldCheck size={14} /> Case export is read-only and tenant-scoped. Review, status, remediation, and export mutations remain server-authorized.</p></aside>;
}

export default function AnalystDrilldown({ api, session, initialEvidence, initialPcapAnalyses }: AnalystDrilldownProps) {
  const [activeView, setActiveView] = useState<DetailView>("assets");
  const readOnlyViewer = session.roles.length > 0 && session.roles.every((role) => role === "viewer");
  const [assets, setAssets] = useState<LoadState<InventoryAsset[]>>({ kind: "loading" });
  const [rules, setRules] = useState<LoadState<DetectionRule[]>>({ kind: "loading" });

  const loadCatalog = useCallback(async (signal?: AbortSignal) => {
    setAssets({ kind: "loading" });
    setRules({ kind: "loading" });
    try {
      const [assetValue, ruleValue] = await Promise.all([
        api.getAssets ? api.getAssets({ limit: 100, signal }) : Promise.resolve([]),
        api.getDetectionRules ? api.getDetectionRules({ signal }) : Promise.resolve([]),
      ]);
      if (signal?.aborted) return;
      setAssets({ kind: "ready", value: assetValue });
      setRules({ kind: "ready", value: ruleValue });
    } catch (error) {
      if (signal?.aborted) return;
      const detail = messageFor(error);
      setAssets({ kind: "error", ...detail });
      setRules({ kind: "error", ...detail });
    }
  }, [api]);

  useEffect(() => {
    const controller = new AbortController();
    void loadCatalog(controller.signal);
    return () => controller.abort();
  }, [loadCatalog]);

  const handleTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>, current: DetailView) => {
    const index = viewOrder.indexOf(current);
    const nextIndex = event.key === "ArrowRight" ? (index + 1) % viewOrder.length : event.key === "ArrowLeft" ? (index - 1 + viewOrder.length) % viewOrder.length : event.key === "Home" ? 0 : event.key === "End" ? viewOrder.length - 1 : -1;
    if (nextIndex < 0) return;
    event.preventDefault();
    const next = viewOrder[nextIndex];
    setActiveView(next);
    document.getElementById(`detail-tab-${next}`)?.focus();
  };

  return <section className="soc-drilldown" id="drilldown" aria-labelledby="soc-drilldown-title"><div className="soc-drilldown__head"><div><span className="soc-card-label">ANALYST WORKSPACE</span><h2 id="soc-drilldown-title">Detail without guesswork.</h2><p>Tenant-scoped asset, detection, evidence, and case records from the authenticated read-only API.</p></div><div className="soc-drilldown__scope"><ShieldCheck size={15} /> {readOnlyViewer ? "Viewer · read-only" : `${session.roles.join(" · ")} · read-only`}</div></div><div className="soc-detail-tabs" role="tablist" aria-label="Analyst detail views">{viewOrder.map((view) => <button id={`detail-tab-${view}`} key={view} type="button" role="tab" aria-selected={activeView === view} aria-controls="detail-panel" tabIndex={activeView === view ? 0 : -1} onClick={() => setActiveView(view)} onKeyDown={(event) => handleTabKeyDown(event, view)}>{view === "assets" ? <HardDrive size={15} /> : view === "detections" ? <Target size={15} /> : view === "evidence" ? <FileSearch size={15} /> : <ListChecks size={15} />}{viewLabels[view]}</button>)}</div><div id="detail-panel" role="tabpanel" tabIndex={0} aria-labelledby={`detail-tab-${activeView}`} className="soc-detail-panel">{activeView === "assets" && <AssetView state={assets} retry={() => void loadCatalog()} />}{activeView === "detections" && <DetectionView state={rules} retry={() => void loadCatalog()} />}{activeView === "evidence" && <EvidenceView evidence={initialEvidence} pcapAnalyses={initialPcapAnalyses} api={api} />}{activeView === "cases" && <CaseView api={api} />}</div></section>;
}
