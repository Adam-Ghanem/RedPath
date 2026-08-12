import { useEffect, useMemo, useState } from "react";

type Campaign = { campaign_id: string; name: string; objective: string; owner: string; status: string; scope_snapshot: string[] };
type Evidence = { evidence_id: string; title: string; evidence_type: string; source: string; technique_id?: string; review_status: string };
type Remediation = { remediation_id: string; finding_title: string; technique_id?: string; owner: string; priority: string; status: string };
type TrendPoint = { period: string; average_risk_score: number; average_coverage_percent: number; run_count: number };
type TuningItem = { technique_id: string; gap_count: number; priority: string; rule_intent: string; event_sources: string[]; regression_fixture: string };
type Integrity = { valid: boolean; event_count: number; tail_digest: string; error: string | null };
type SlaItem = { remediation_id: string; finding_title: string; priority: string; status: string; owner: string; due_date: string; target_days: number; state: string };

const API_BASE = "/api/v1";

const seededCampaign: Campaign = {
  campaign_id: "demo-identity-review",
  name: "Q3 Identity Exposure Review",
  objective: "Prioritize identity paths and close detection gaps in the isolated lab.",
  owner: "blue-team",
  status: "active",
  scope_snapshot: ["192.168.56.0/24"],
};

const seededTrend: TrendPoint[] = [
  { period: "D-6", average_risk_score: 62, average_coverage_percent: 48, run_count: 2 },
  { period: "D-5", average_risk_score: 67, average_coverage_percent: 52, run_count: 1 },
  { period: "D-4", average_risk_score: 73, average_coverage_percent: 58, run_count: 2 },
  { period: "D-3", average_risk_score: 69, average_coverage_percent: 61, run_count: 1 },
  { period: "D-2", average_risk_score: 78, average_coverage_percent: 66, run_count: 2 },
  { period: "D-1", average_risk_score: 71, average_coverage_percent: 72, run_count: 1 },
];

export default function ExpertOpsPanel({ apiOnline, onActivity }: { apiOnline: boolean; onActivity: (message: string) => void }) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([seededCampaign]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [trend, setTrend] = useState<TrendPoint[]>(seededTrend);
  const [tuning, setTuning] = useState<TuningItem[]>([]);
  const [integrity, setIntegrity] = useState<Integrity>({ valid: true, event_count: 0, tail_digest: "GENESIS", error: null });
  const [sla, setSla] = useState<SlaItem[]>([]);
  const [selectedId, setSelectedId] = useState(seededCampaign.campaign_id);
  const [creating, setCreating] = useState(false);
  const selected = useMemo(() => campaigns.find((item) => item.campaign_id === selectedId) ?? campaigns[0], [campaigns, selectedId]);

  useEffect(() => {
    if (!apiOnline) return;
    Promise.all([
      fetch(`${API_BASE}/campaigns`),
      fetch(`${API_BASE}/evidence`),
      fetch(`${API_BASE}/remediations`),
      fetch(`${API_BASE}/trends/risk`),
      fetch(`${API_BASE}/detection-tuning`),
      fetch(`${API_BASE}/integrity/audit`),
      fetch(`${API_BASE}/remediations/sla`),
    ]).then(async ([campaignResponse, evidenceResponse, remediationResponse, trendResponse, tuningResponse, integrityResponse, slaResponse]) => {
      if (campaignResponse.ok) {
        const items = await campaignResponse.json();
        setCampaigns(items.length ? items : [seededCampaign]);
        if (items.length) setSelectedId(items[0].campaign_id);
      }
      if (evidenceResponse.ok) setEvidence(await evidenceResponse.json());
      if (remediationResponse.ok) setRemediations(await remediationResponse.json());
      if (trendResponse.ok) setTrend(await trendResponse.json());
      if (tuningResponse.ok) setTuning(await tuningResponse.json());
      if (integrityResponse.ok) setIntegrity(await integrityResponse.json());
      if (slaResponse.ok) setSla(await slaResponse.json());
    }).catch(() => onActivity("Expert operations API unavailable; seeded campaign workspace remains active."));
  }, [apiOnline, onActivity]);

  async function createCampaign() {
    if (!apiOnline) {
      onActivity("Demo campaign staged locally; connect the API to persist it.");
      return;
    }
    setCreating(true);
    try {
      const response = await fetch(`${API_BASE}/campaigns`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `Lab Campaign ${campaigns.length + 1}`,
          objective: "Review identity exposure, detection coverage, and remediation ownership.",
          owner: "security-team",
          scope_snapshot: ["192.168.56.0/24"],
        }),
      });
      if (!response.ok) throw new Error("campaign create failed");
      const campaign = await response.json();
      setCampaigns((current) => [campaign, ...current]);
      setSelectedId(campaign.campaign_id);
      onActivity(`Campaign created: ${campaign.name}.`);
    } catch {
      onActivity("Campaign creation failed safely; no external system was modified.");
    } finally {
      setCreating(false);
    }
  }

  async function exportCampaign() {
    if (!selected || !apiOnline) {
      onActivity("Export is staged in demo mode; connect the API for a deterministic package.");
      return;
    }
    const response = await fetch(`${API_BASE}/campaigns/${selected.campaign_id}/export`);
    if (!response.ok) {
      onActivity("Campaign export failed safely; no external system was modified.");
      return;
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${selected.campaign_id}-export.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    onActivity(`Exported evidence package for ${selected.name}.`);
  }

  const maxRisk = Math.max(...trend.map((item) => item.average_risk_score), 1);
  return (
    <section id="campaigns" className="expert-ops-grid">
      <article className="panel control-posture">
        <div className="panel-heading"><div><span className="eyebrow">Enterprise controls / chain of custody</span><h3>Integrity & export posture</h3></div><span className={`integrity-badge ${integrity.valid ? "valid" : "invalid"}`}>{integrity.valid ? "CHAIN VALID" : "CHAIN BROKEN"}</span></div>
        <div className="control-posture-grid"><div><strong>{integrity.event_count}</strong><small>audit events verified</small></div><div><strong>{sla.filter((item) => item.state === "overdue").length}</strong><small>overdue SLA actions</small></div><div><strong>{evidence.length}</strong><small>evidence records</small></div><button className="small-button" onClick={exportCampaign}>Export campaign package</button></div>
      </article>
      <article className="panel campaign-panel">
        <div className="panel-heading"><div><span className="eyebrow">Operations / campaign context</span><h3>Assessment campaigns</h3></div><button className="small-button" onClick={createCampaign} disabled={creating}>{creating ? "Creating…" : "+ New campaign"}</button></div>
        <div className="campaign-list">{campaigns.map((campaign) => <button className={`campaign-row ${selected?.campaign_id === campaign.campaign_id ? "selected" : ""}`} key={campaign.campaign_id} onClick={() => setSelectedId(campaign.campaign_id)}><span className="campaign-status" /><span><strong>{campaign.name}</strong><small>{campaign.owner} · {campaign.scope_snapshot.join(", ")}</small></span><em>{campaign.status}</em></button>)}</div>
        {selected && <div className="campaign-summary"><span className="eyebrow">Active objective</span><strong>{selected.objective}</strong><div className="campaign-counts"><span><b>{evidence.filter((item) => !selected || item.evidence_id).length}</b> evidence</span><span><b>{remediations.length}</b> remediations</span><span><b>{tuning.length}</b> tuning gaps</span></div></div>}
      </article>

      <article className="panel trend-panel">
        <div className="panel-heading"><div><span className="eyebrow">Posture analytics / historical</span><h3>Risk vs coverage</h3></div><span className="panel-tag">EXPLAINABLE</span></div>
        <div className="trend-legend"><span><i className="trend-risk" />Risk</span><span><i className="trend-coverage" />Coverage</span></div>
        <div className="trend-bars">{trend.map((item) => <div className="trend-column" key={item.period}><div className="trend-bar-stack"><span className="trend-risk-bar" style={{ height: `${(item.average_risk_score / maxRisk) * 100}%` }} /><span className="trend-coverage-bar" style={{ height: `${item.average_coverage_percent}%` }} /></div><small>{item.period}</small></div>)}</div>
        <div className="trend-callout"><strong>{trend.length ? `${Math.round(trend[trend.length - 1].average_coverage_percent)}%` : "--"}</strong><span>latest detection coverage<br />derived from persisted runs</span></div>
      </article>

      <article className="panel tuning-panel">
        <div className="panel-heading"><div><span className="eyebrow">Detection engineering / queue</span><h3>Rule-tuning backlog</h3></div><span className="coverage-number">{tuning.length.toString().padStart(2, "0")}</span></div>
        <div className="tuning-list">{tuning.length === 0 ? <div className="expert-empty">No imported gaps yet.<small>Scenario runs populate this queue.</small></div> : tuning.slice(0, 4).map((item) => <div className="tuning-row" key={item.technique_id}><div><strong>{item.technique_id}</strong><small>{item.rule_intent}</small></div><span className={`priority-pill ${item.priority}`}>{item.priority}</span></div>)}</div>
      </article>

      <article className="panel remediation-panel">
        <div className="panel-heading"><div><span className="eyebrow">Remediation governance / ownership</span><h3>Open actions</h3></div><a className="text-link" href="#findings">View queue →</a></div>
        <div className="remediation-board">{remediations.length === 0 ? <div className="expert-empty">No actions registered.<small>Create remediations from findings and scenario gaps.</small></div> : remediations.slice(0, 3).map((item) => <div className="remediation-card" key={item.remediation_id}><span className={`priority-pill ${item.priority}`}>{item.priority}</span><strong>{item.finding_title}</strong><small>{item.owner} · {item.status}</small></div>)}</div>
      </article>
    </section>
  );
}
