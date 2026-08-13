import type { AnalystConsoleSnapshot, AssessmentRunSummary, ConsoleSeverity, RemediationSlaItem } from "./contracts";

export type PriorityLabel = "Critical" | "High" | "Medium" | "Low" | "Info";

export type AnalystConsoleModel = {
  posture: {
    riskScore: number;
    riskLabel: PriorityLabel;
    coveragePercent: number;
    effectiveCoveragePercent: number;
    openCriticalFindings: number;
    openGaps: number;
    overdueRemediations: number;
  };
  evidence: {
    reviewed: number;
    pending: number;
    integrityValid: boolean;
    auditEvents: number;
  };
  safety: {
    dryRunDefault: boolean;
    allowedCidrs: string[];
  };
  remediationQueue: RemediationSlaItem[];
  tuningQueue: AnalystConsoleSnapshot["detectionTuning"];
  recentRuns: AssessmentRunSummary[];
};

const severityRank: Record<ConsoleSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function clampPercent(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function riskLabel(score: number): PriorityLabel {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  if (score > 0) return "Low";
  return "Info";
}

function remediationRank(item: RemediationSlaItem) {
  const stateRank = item.state === "overdue" ? 0 : item.state === "due_soon" ? 1 : item.state === "on_track" ? 2 : 3;
  return [stateRank, severityRank[item.priority]] as const;
}

function sortRemediations(items: RemediationSlaItem[]) {
  return [...items].sort((left, right) => {
    const [leftState, leftSeverity] = remediationRank(left);
    const [rightState, rightSeverity] = remediationRank(right);
    return leftState - rightState || leftSeverity - rightSeverity || left.finding_title.localeCompare(right.finding_title);
  });
}

export function formatUtc(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Timestamp unavailable";
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

export function buildAnalystConsoleModel(snapshot: AnalystConsoleSnapshot): AnalystConsoleModel {
  const reviewed = snapshot.evidence.filter((item) => item.review_status === "accepted").length;
  const pending = snapshot.evidence.length - reviewed;

  return {
    posture: {
      riskScore: clampPercent(snapshot.executiveKpis.risk_score),
      riskLabel: riskLabel(snapshot.executiveKpis.risk_score),
      coveragePercent: clampPercent(snapshot.coverage.coverage_percent),
      effectiveCoveragePercent: clampPercent(snapshot.coverage.effective_coverage_percent),
      openCriticalFindings: snapshot.executiveKpis.open_critical_findings,
      openGaps: snapshot.coverage.open_gaps,
      overdueRemediations: snapshot.executiveKpis.overdue_remediations,
    },
    evidence: {
      reviewed,
      pending,
      integrityValid: snapshot.integrity.valid,
      auditEvents: snapshot.integrity.event_count,
    },
    safety: {
      dryRunDefault: snapshot.scope.dry_run_default,
      allowedCidrs: snapshot.scope.allowed_cidrs,
    },
    remediationQueue: sortRemediations(snapshot.remediationSla),
    tuningQueue: [...snapshot.detectionTuning].sort((left, right) => severityRank[left.priority] - severityRank[right.priority] || right.gap_count - left.gap_count),
    recentRuns: [...snapshot.runs].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at)),
  };
}
