export type ConsoleSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ScopeResponse = {
  allowed_cidrs: string[];
  dry_run_default: boolean;
};

export type ExecutiveKpis = {
  risk_score: number;
  detection_coverage_percent: number;
  effective_coverage_percent: number;
  open_critical_findings: number;
  overdue_remediations: number;
  expiring_acceptances: number;
  evidence_review_backlog: number;
};

export type CoverageScorecard = {
  expected_techniques: number;
  detected_techniques: number;
  open_gaps: number;
  accepted_risks: number;
  coverage_percent: number;
  effective_coverage_percent: number;
};

export type AssessmentRunSummary = {
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

export type EvidenceResponse = {
  evidence_id: string;
  campaign_id?: string | null;
  run_id?: string | null;
  evidence_type: string;
  source: string;
  title: string;
  sha256: string;
  technique_id?: string | null;
  notes: string;
  review_status: "unreviewed" | "in_review" | "accepted" | "rejected" | string;
  reviewer?: string | null;
  reviewed_at?: string | null;
  created_at: string;
};

export type PcapFlowSummary = {
  flow_id: string;
  protocol: "tcp" | "udp" | "icmp" | "other";
  source: string;
  destination: string;
  source_port?: number | null;
  destination_port?: number | null;
  packet_count: number;
  byte_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
};

export type PcapDnsSummary = {
  query: string;
  count: number;
  first_seen?: string | null;
  last_seen?: string | null;
};

export type PcapAnalysisSummary = {
  analysis_id: string;
  tenant_id: string;
  evidence_id: string;
  file_name: string;
  sha256: string;
  capture_format: "pcap" | "pcapng";
  packet_count: number;
  campaign_id?: string | null;
  evidence_title?: string | null;
  review_status: string;
  redaction_mode: "pseudonymized";
  redacted_fields: number;
  flow_count: number;
  dns_count: number;
  created_at: string;
};

export type PcapAnalysisDetail = PcapAnalysisSummary & {
  file_size: number;
  first_packet_at?: string | null;
  last_packet_at?: string | null;
  protocol_counts: Record<string, number>;
  endpoints: Array<{ ip: string; packet_count: number; byte_count: number }>;
  dns_queries: string[];
  observations: Array<{
    timestamp_utc: string;
    observation_type: string;
    protocol: string;
    source_ip?: string | null;
    destination_ip?: string | null;
    source_port?: number | null;
    destination_port?: number | null;
    attributes: Record<string, unknown>;
  }>;
  flows: PcapFlowSummary[];
  dns_summary: PcapDnsSummary[];
  warnings: string[];
};

export type PcapEvidenceView = {
  evidence: EvidenceResponse;
  analysis: PcapAnalysisDetail;
};

export type RemediationSlaItem = {
  remediation_id: string;
  finding_title: string;
  priority: ConsoleSeverity;
  status: "open" | "in_progress" | "blocked" | "resolved" | "closed" | string;
  owner: string;
  due_date?: string | null;
  target_days: number;
  state: "on_track" | "due_soon" | "overdue" | "closed";
};

export type DetectionTuningItem = {
  technique_id: string;
  gap_count: number;
  priority: "high" | "medium" | "low";
  rule_intent: string;
  event_sources: string[];
  regression_fixture: string;
};

export type IntegrityVerification = {
  valid: boolean;
  event_count: number;
  tail_digest: string;
  first_invalid_event_id?: string | null;
  error?: string | null;
};

export type AnalystConsoleSnapshot = {
  scope: ScopeResponse;
  executiveKpis: ExecutiveKpis;
  coverage: CoverageScorecard;
  runs: AssessmentRunSummary[];
  evidence: EvidenceResponse[];
  pcapAnalyses: PcapAnalysisSummary[];
  remediationSla: RemediationSlaItem[];
  detectionTuning: DetectionTuningItem[];
  integrity: IntegrityVerification;
};

export type SnapshotLoadState =
  | { kind: "loading" }
  | { kind: "ready"; snapshot: AnalystConsoleSnapshot; refreshedAt: Date }
  | { kind: "error"; message: string };

export type ConsoleApi = {
  getSnapshot: () => Promise<AnalystConsoleSnapshot>;
  getPcapEvidenceView: (evidenceId: string) => Promise<PcapEvidenceView>;
};
