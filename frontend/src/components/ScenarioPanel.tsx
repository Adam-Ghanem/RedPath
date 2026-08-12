import { useEffect, useMemo, useState } from "react";

type Scenario = {
  scenario_id: string;
  name: string;
  objective: string;
  tactics: string[];
  technique_ids: string[];
  estimated_minutes: number;
  safety_notes: string[];
};

type RunSummary = {
  run_id: string;
  scenario_id: string;
  status: string;
  dry_run: boolean;
  risk_score: number;
  coverage_percent: number;
  finding_count: number;
  gap_count: number;
  summary: string;
  created_at: string;
};

const API_BASE = "/api/v1";

const fallbackScenarios: Scenario[] = [
  {
    scenario_id: "ad.identity-exposure-baseline",
    name: "AD identity exposure baseline",
    objective: "Review synthetic identity conditions that can create credential-access paths.",
    tactics: ["Credential Access", "Privilege Escalation"],
    technique_ids: ["T1558.003", "T1558.004"],
    estimated_minutes: 15,
    safety_notes: ["Observation-only", "No ticket requests", "Dry-run enforced"],
  },
  {
    scenario_id: "ad.adcs-template-review",
    name: "ADCS template review",
    objective: "Review certificate-template metadata for authentication-certificate abuse paths.",
    tactics: ["Credential Access", "Privilege Escalation"],
    technique_ids: ["T1649"],
    estimated_minutes: 20,
    safety_notes: ["Metadata-only", "No enrollment", "Lab scope locked"],
  },
  {
    scenario_id: "purple.kerberos-detection-battle",
    name: "Kerberos detection battle",
    objective: "Compare expected Kerberos signals against imported Wazuh evidence.",
    tactics: ["Credential Access"],
    technique_ids: ["T1558.003", "T1558.004"],
    estimated_minutes: 25,
    safety_notes: ["Synthetic events", "Read-only alerts", "No attack tooling"],
  },
];

function demoPayload(scenarioId: string) {
  const observations = scenarioId.includes("adcs")
    ? [{ asset_id: "CA-01", adcs_template: "Lab-User-Auth", enrollee_supplies_subject: true, client_auth_eku: true }]
    : [
        { asset_id: "DC-01", service_principal_name: "MSSQLSvc/db01.lab.local:1433" },
        { asset_id: "USER-07", preauth_disabled: true },
      ];
  const alerts = scenarioId.includes("kerberos")
    ? [{ id: "demo-alert-001", rule: { description: "T1558.003 Kerberoasting signal" } }]
    : [{ id: "demo-alert-002", rule: { description: "T1649 certificate issuance" } }];
  return { scenario_id: scenarioId, observations, alerts, dry_run: true };
}

export default function ScenarioPanel({ apiOnline, onActivity }: { apiOnline: boolean; onActivity: (message: string) => void }) {
  const [scenarios, setScenarios] = useState<Scenario[]>(fallbackScenarios);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedId, setSelectedId] = useState(fallbackScenarios[0].scenario_id);
  const [loading, setLoading] = useState(false);
  const selected = useMemo(() => scenarios.find((item) => item.scenario_id === selectedId) ?? scenarios[0], [scenarios, selectedId]);

  useEffect(() => {
    if (!apiOnline) return;
    Promise.all([fetch(`${API_BASE}/scenarios`), fetch(`${API_BASE}/runs`)]).then(async ([scenarioResponse, runResponse]) => {
      if (scenarioResponse.ok) setScenarios(await scenarioResponse.json());
      if (runResponse.ok) setRuns(await runResponse.json());
    }).catch(() => onActivity("API history unavailable; showing seeded scenario catalog."));
  }, [apiOnline, onActivity]);

  async function runScenario() {
    if (!selected) return;
    setLoading(true);
    onActivity(`Launching ${selected.name} in dry-run mode…`);
    try {
      const response = await fetch(`${API_BASE}/scenarios/${selected.scenario_id}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(demoPayload(selected.scenario_id)),
      });
      if (!response.ok) throw new Error("Scenario API unavailable");
      const result: RunSummary = await response.json();
      setRuns((current) => [result, ...current.filter((item) => item.run_id !== result.run_id)]);
      onActivity(`${selected.name}: ${result.finding_count} findings, ${result.coverage_percent}% coverage, ${result.gap_count} gaps.`);
    } catch {
      onActivity(`Demo run staged for ${selected.name}; no commands executed.`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section id="scenarios" className="scenario-layout">
      <article className="panel scenario-panel">
        <div className="panel-heading"><div><span className="eyebrow">Scenario library / safe execution</span><h3>Assessment playbooks</h3></div><span className="panel-tag">{scenarios.length} PACKS</span></div>
        <div className="scenario-list">
          {scenarios.map((scenario) => (
            <button className={`scenario-card ${selected?.scenario_id === scenario.scenario_id ? "selected" : ""}`} key={scenario.scenario_id} onClick={() => setSelectedId(scenario.scenario_id)}>
              <span className="scenario-index">{String(scenarios.indexOf(scenario) + 1).padStart(2, "0")}</span>
              <span><strong>{scenario.name}</strong><small>{scenario.objective}</small><em>{scenario.technique_ids.join(" · ")}</em></span>
              <span className="scenario-time">{scenario.estimated_minutes}m</span>
            </button>
          ))}
        </div>
        {selected && <div className="scenario-detail"><div><span className="eyebrow">Selected playbook</span><strong>{selected.name}</strong><p>{selected.objective}</p><div className="scenario-tags">{selected.safety_notes.map((note) => <span key={note}>{note}</span>)}</div></div><button className="primary-button" onClick={runScenario} disabled={loading}>{loading ? "Running…" : "Run dry-run"}</button></div>}
      </article>
      <article className="panel run-history-panel">
        <div className="panel-heading"><div><span className="eyebrow">Assessment history / evidence</span><h3>Recent runs</h3></div><span className="coverage-number">{runs.length.toString().padStart(2, "0")}</span></div>
        <div className="run-history">
          {runs.length === 0 ? <div className="empty-state"><span className="status-pulse muted" />No persisted runs yet.<small>Run a playbook to create an auditable history record.</small></div> : runs.slice(0, 4).map((run) => <div className="run-row" key={run.run_id}><div><strong>{run.scenario_id.split(".")[run.scenario_id.split(".").length - 1]}</strong><small>{run.finding_count} findings · {run.gap_count} gaps</small></div><span className="run-score">{Math.round(run.risk_score)}<small>risk</small></span><span className="run-coverage">{run.coverage_percent}%<small>coverage</small></span></div>)}
        </div>
      </article>
    </section>
  );
}
