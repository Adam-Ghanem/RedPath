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

export type PcapAnalysisSummary = {
  analysis_id: string;
  evidence_id: string;
  tenant_id: string;
  file_name: string;
  sha256: string;
  capture_format: string;
  packet_count: number;
  campaign_id?: string | null;
  evidence_title?: string | null;
  review_status: string;
  redaction_mode: string;
  redacted_fields: number;
  flow_count: number;
  dns_count: number;
  created_at: string;
};

export type PcapEvidenceView = {
  evidence: EvidenceResponse;
  analysis: Record<string, unknown>;
};

export type AssetProvenance = {
  source: string;
  scan_id: string;
  job_id: string;
  actor: string;
  observed_at: string;
  dry_run: boolean;
  observation_hash: string;
};

export type InventoryAsset = {
  schema_version: "1.0" | string;
  asset: Record<string, unknown>;
  asset_id: string;
  tenant_id: string;
  display_name: string;
  asset_type: "host" | string;
  ip: string;
  hostname?: string | null;
  ports: number[];
  services: string[];
  scan_id: string;
  source: string;
  discovered_at: string;
  first_seen_at: string;
  last_seen_at: string;
  provenance: AssetProvenance;
};

export type DetectionCondition = {
  path: string;
  operator: "equals" | "contains" | "starts_with" | "in" | string;
  value: unknown;
};

export type DetectionRule = {
  rule_id: string;
  version: number;
  title: string;
  description: string;
  technique_ids: string[];
  severity: ConsoleSeverity;
  event_sources: string[];
  conditions: DetectionCondition[];
  match_mode: "all" | "any" | string;
  window_seconds: number;
  group_by: string[];
  enabled: boolean;
  false_positive_sla_percent: number;
  deployment_status: "draft" | "testing" | "production" | string;
  requires_approval: boolean;
};

export type CampaignResponse = {
  name: string;
  objective: string;
  scope_snapshot: string[];
  tenant_id: string;
  owner: string;
  campaign_id: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type GovernanceHistoryEvent = {
  event_id: string;
  tenant_id: string;
  case_id: string;
  event_type: string;
  actor: string;
  summary: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type RemediationResponse = {
  campaign_id?: string | null;
  finding_title: string;
  technique_id?: string | null;
  recommendation: string;
  owner: string;
  priority: ConsoleSeverity;
  due_date?: string | null;
  tenant_id: string;
  remediation_id: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type EvidenceManifest = {
  evidence_id: string;
  canonical_payload: string;
  manifest_sha256: string;
  generated_at: string;
};

export type CampaignExport = {
  tenant_id: string;
  campaign: CampaignResponse;
  timeline: Array<{ event_type: string; reference_id: string; title: string; status: string; occurred_at: string }>;
  evidence: EvidenceResponse[];
  remediations: RemediationResponse[];
  governance_history: GovernanceHistoryEvent[];
  trend: Array<{ period: string; average_risk_score: number; average_coverage_percent: number; run_count: number }>;
  detection_tuning: DetectionTuningItem[];
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

export type AuthLoginRequest = {
  tenant_slug: string;
  username: string;
  password: string;
};

export type AuthTokenResponse = {
  access_token: string;
  token_type: "bearer";
  expires_at: string;
  user_id: string;
  username: string;
  tenant_id: string;
  tenant_slug: string;
  roles: string[];
};

export type AuthMeResponse = {
  user_id: string;
  username: string;
  tenant_id: string;
  tenant_slug: string;
  roles: string[];
  session_version: number;
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
  | { kind: "auth-required"; message: string }
  | { kind: "ready"; snapshot: AnalystConsoleSnapshot; session: AuthMeResponse; refreshedAt: Date }
  | { kind: "error"; message: string; status?: number };

export type ConsoleApi = {
  getSession?: () => Promise<AuthMeResponse>;
  getSnapshot: (options?: { signal?: AbortSignal }) => Promise<AnalystConsoleSnapshot>;
  login?: (request: AuthLoginRequest) => Promise<AuthTokenResponse>;
  logout?: () => void;
  getAssets?: (options?: { limit?: number; signal?: AbortSignal }) => Promise<InventoryAsset[]>;
  getDetectionRules?: (options?: { signal?: AbortSignal }) => Promise<DetectionRule[]>;
  getCases?: (options?: { signal?: AbortSignal }) => Promise<CampaignResponse[]>;
  getCaseExport?: (caseId: string, options?: { signal?: AbortSignal }) => Promise<CampaignExport>;
  getEvidenceManifest?: (evidenceId: string, options?: { signal?: AbortSignal }) => Promise<EvidenceManifest>;
  getPcapEvidenceView?: (evidenceId: string, options?: { signal?: AbortSignal }) => Promise<PcapEvidenceView>;
};
