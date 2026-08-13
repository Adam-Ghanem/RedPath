import { describe, expect, it } from "vitest";
import type { AnalystConsoleSnapshot } from "../contracts";
import { buildAnalystConsoleModel, clampPercent, formatUtc, riskLabel } from "../model";

const snapshot: AnalystConsoleSnapshot = {
  scope: { allowed_cidrs: ["192.0.2.0/24"], dry_run_default: true },
  executiveKpis: {
    risk_score: 87.4,
    detection_coverage_percent: 70,
    effective_coverage_percent: 62,
    open_critical_findings: 2,
    overdue_remediations: 1,
    expiring_acceptances: 0,
    evidence_review_backlog: 2,
  },
  coverage: { expected_techniques: 10, detected_techniques: 7, open_gaps: 3, accepted_risks: 0, coverage_percent: 70, effective_coverage_percent: 62 },
  runs: [
    { run_id: "run-old", scenario_id: "identity", status: "completed", dry_run: true, risk_score: 32, coverage_percent: 70, finding_count: 1, gap_count: 2, summary: "Older run", created_at: "2026-08-10T08:00:00Z" },
    { run_id: "run-new", scenario_id: "endpoint", status: "completed", dry_run: true, risk_score: 40, coverage_percent: 72, finding_count: 2, gap_count: 1, summary: "Newer run", created_at: "2026-08-12T08:00:00Z" },
  ],
  evidence: [
    { evidence_id: "e-1", evidence_type: "pcap", source: "lab", title: "Accepted capture", sha256: "a".repeat(64), notes: "", review_status: "accepted", created_at: "2026-08-10T08:00:00Z" },
    { evidence_id: "e-2", evidence_type: "event", source: "lab", title: "Pending event", sha256: "b".repeat(64), notes: "", review_status: "in_review", created_at: "2026-08-11T08:00:00Z" },
  ],
  pcapAnalyses: [],
  remediationSla: [
    { remediation_id: "r-ontrack", finding_title: "Later remediation", priority: "critical", status: "open", owner: "network", due_date: "2026-08-20", target_days: 7, state: "on_track" },
    { remediation_id: "r-overdue-high", finding_title: "Overdue high", priority: "high", status: "open", owner: "identity", due_date: "2026-08-01", target_days: 7, state: "overdue" },
    { remediation_id: "r-overdue-critical", finding_title: "Overdue critical", priority: "critical", status: "open", owner: "identity", due_date: "2026-08-01", target_days: 7, state: "overdue" },
  ],
  detectionTuning: [
    { technique_id: "T1000", gap_count: 1, priority: "medium", rule_intent: "Medium priority", event_sources: [], regression_fixture: "fixture-a" },
    { technique_id: "T2000", gap_count: 1, priority: "high", rule_intent: "High priority", event_sources: [], regression_fixture: "fixture-b" },
  ],
  integrity: { valid: true, event_count: 12, tail_digest: "digest" },
};

describe("analyst console model", () => {
  it("prioritises overdue critical remediation and newest assessment activity", () => {
    const model = buildAnalystConsoleModel(snapshot);

    expect(model.posture).toMatchObject({ riskScore: 87, riskLabel: "Critical", coveragePercent: 70, effectiveCoveragePercent: 62, openGaps: 3 });
    expect(model.evidence).toEqual({ reviewed: 1, pending: 1, integrityValid: true, auditEvents: 12 });
    expect(model.remediationQueue.map((item) => item.remediation_id)).toEqual(["r-overdue-critical", "r-overdue-high", "r-ontrack"]);
    expect(model.tuningQueue.map((item) => item.technique_id)).toEqual(["T2000", "T1000"]);
    expect(model.recentRuns.map((run) => run.run_id)).toEqual(["run-new", "run-old"]);
  });

  it("classifies risk and clamps values presented as percentages", () => {
    expect(riskLabel(0)).toBe("Info");
    expect(riskLabel(30)).toBe("Medium");
    expect(riskLabel(80)).toBe("Critical");
    expect(clampPercent(-2)).toBe(0);
    expect(clampPercent(42.6)).toBe(43);
    expect(clampPercent(140)).toBe(100);
  });

  it("renders invalid service timestamps safely rather than throwing", () => {
    expect(formatUtc("not-a-timestamp")).toBe("Timestamp unavailable");
  });
});
