from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class ReconRequest(BaseModel):
    targets: list[IPvAnyAddress] = Field(min_length=1)
    profile: Literal["safe", "service_inventory"] = "safe"
    dry_run: bool = True


class ReconCommand(BaseModel):
    tool: str
    argv: list[str]
    purpose: str
    executed: bool = False


class AssetObservation(BaseModel):
    model_config = ConfigDict(extra="allow")

    ip: str
    hostname: str | None = None
    ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    source: str = "recon"


class ReconResult(BaseModel):
    scan_id: str
    dry_run: bool
    targets: list[str]
    commands: list[ReconCommand]
    assets: list[AssetObservation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class FindingInput(BaseModel):
    title: str
    description: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    asset_id: str | None = None
    technique_id: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class AttackNode(BaseModel):
    id: str
    label: str
    kind: Literal["asset", "identity", "finding", "privilege"]
    criticality: float = Field(default=0.0, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)
    zone: Literal["on_prem", "cloud", "hybrid", "unknown"] = "unknown"
    is_entry_point: bool = False
    is_crown_jewel: bool = False


class AttackEdge(BaseModel):
    source: str
    target: str
    technique_id: str | None = None
    weight: float = Field(default=1.0, gt=0)
    rationale: str = ""
    category: Literal[
        "credential_theft",
        "lateral_movement",
        "privilege_escalation",
        "persistence",
        "cloud_privilege_abuse",
        "other",
    ] = "other"
    likelihood: float = Field(default=5.0, ge=0, le=10)
    impact: float = Field(default=5.0, ge=0, le=10)
    stealth: float = Field(default=5.0, ge=0, le=10)
    prerequisites: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    hardening_action: str = "Review and harden the control represented by this edge."
    estimated_effort_hours: int = Field(default=4, ge=1, le=10_000)
    hybrid: bool = False


class RiskFactor(BaseModel):
    dimension: Literal["likelihood", "impact", "stealth"]
    score: float = Field(ge=0, le=10)
    weight: float = Field(ge=0, le=1)
    weighted_contribution: float = Field(ge=0, le=10)
    evidence: list[str] = Field(default_factory=list)


class RiskExplanation(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    factors: list[RiskFactor] = Field(min_length=1)
    assumptions: list[str] = Field(default_factory=list)
    mitigation: list[str] = Field(default_factory=list)


class RankedAttackPath(BaseModel):
    path_id: str
    hops: list[str] = Field(min_length=2)
    edges: list[AttackEdge] = Field(min_length=1)
    category: str
    composite_score: float = Field(ge=0, le=10)
    risk_score: float = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical"]
    likelihood: float = Field(ge=0, le=10)
    impact: float = Field(ge=0, le=10)
    stealth: float = Field(ge=0, le=10)
    mitre_techniques: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    is_hybrid: bool = False
    explanation: RiskExplanation


class ChokePoint(BaseModel):
    node_id: str
    label: str
    paths_blocked: int = Field(ge=1)
    path_ids: list[str] = Field(min_length=1)
    priority_class: Literal["P0", "P1", "P2", "P3"]
    hardening_action: str = Field(min_length=1, max_length=2000)
    estimated_effort_hours: int = Field(ge=1, le=10_000)
    rationale: str = Field(min_length=1, max_length=2000)


class GraphSummary(BaseModel):
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    entry_point_count: int = Field(ge=0)
    crown_jewel_count: int = Field(ge=0)
    viable_path_count: int = Field(ge=0)
    critical_path_count: int = Field(ge=0)
    hybrid_path_count: int = Field(ge=0)
    truncated: bool = False


class AttackPathAnalysisRequest(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    tenant_id: str = Field(min_length=1, max_length=128)
    nodes: list[AttackNode] = Field(min_length=1, max_length=5000)
    edges: list[AttackEdge] = Field(default_factory=list, max_length=20_000)
    entry_point_ids: list[str] = Field(default_factory=list, max_length=100)
    crown_jewel_ids: list[str] = Field(default_factory=list, max_length=100)
    max_hops: int = Field(default=8, ge=1, le=12)
    max_paths: int = Field(default=100, ge=1, le=500)
    critical_threshold: float = Field(default=7.0, ge=0, le=10)


class AttackPathAnalysisResponse(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    tenant_id: str
    graph_summary: GraphSummary
    entry_points: list[str]
    crown_jewel_nodes: list[str]
    ranked_paths: list[RankedAttackPath]
    choke_points: list[ChokePoint]
    cloud_paths: list[str]
    unreachable_crown_jewels: list[str]
    warnings: list[str] = Field(default_factory=list)


class GraphRequest(BaseModel):
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    source_node: str
    target_node: str = "domain-admin"


class AttackPath(BaseModel):
    nodes: list[str]
    edges: list[AttackEdge]
    total_weight: float


class GraphResult(BaseModel):
    paths: list[AttackPath]
    chokepoints: list[dict[str, Any]]


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str
    detection_guidance: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class CoverageObservation(BaseModel):
    technique_id: str
    expected: bool = True
    detected: bool = False
    evidence_count: int = Field(default=0, ge=0)
    alert_ids: list[str] = Field(default_factory=list)
    recommendation: str = ""


class CorrelationRequest(BaseModel):
    findings: list[FindingInput] = Field(default_factory=list)
    graph: GraphResult | None = None


class CorrelatedRisk(BaseModel):
    finding_title: str
    technique_id: str | None = None
    asset_id: str | None = None
    risk_score: float = Field(ge=0, le=100)
    path_relevance: float = Field(ge=0, le=1)
    related_techniques: list[str] = Field(default_factory=list)
    rationale: str


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str | None = None
    rule: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str | None = None


class ScenarioSpec(BaseModel):
    scenario_id: str
    name: str
    objective: str
    tactics: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    estimated_minutes: int = Field(default=10, ge=1, le=240)


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    observations: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[WazuhAlert] = Field(default_factory=list)
    dry_run: bool = True


class AssessmentRunSummary(BaseModel):
    run_id: str
    scenario_id: str
    status: str
    dry_run: bool
    risk_score: float = Field(ge=0, le=100)
    coverage_percent: float = Field(ge=0, le=100)
    finding_count: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    summary: str
    created_at: datetime


class ScenarioRunResponse(AssessmentRunSummary):
    findings: list[FindingInput] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class CampaignCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    objective: str = Field(min_length=10, max_length=2000)
    owner: str = Field(default="security-team", min_length=2, max_length=128)
    scope_snapshot: list[str] = Field(default_factory=list)


class CampaignResponse(CampaignCreate):
    campaign_id: str
    status: str
    created_at: datetime
    updated_at: datetime


class EvidenceCreate(BaseModel):
    campaign_id: str | None = None
    run_id: str | None = None
    evidence_type: str = Field(min_length=2, max_length=64)
    source: str = Field(min_length=2, max_length=255)
    title: str = Field(min_length=3, max_length=255)
    sha256: str = Field(min_length=64, max_length=64)
    technique_id: str | None = None
    notes: str = Field(default="", max_length=4000)


class EvidenceResponse(EvidenceCreate):
    evidence_id: str
    review_status: str
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime


class EvidenceReviewUpdate(BaseModel):
    review_status: Literal["unreviewed", "in_review", "accepted", "rejected"]
    reviewer: str = Field(min_length=2, max_length=128)
    notes: str = Field(default="", max_length=4000)


class RemediationCreate(BaseModel):
    campaign_id: str | None = None
    finding_title: str = Field(min_length=3, max_length=255)
    technique_id: str | None = None
    recommendation: str = Field(min_length=10, max_length=4000)
    owner: str = Field(default="unassigned", min_length=2, max_length=128)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    due_date: str | None = None


class RemediationResponse(RemediationCreate):
    remediation_id: str
    status: str
    created_at: datetime
    updated_at: datetime


class RemediationLifecycleUpdate(BaseModel):
    status: Literal["open", "in_progress", "blocked", "resolved", "closed"]
    actor: str = Field(min_length=2, max_length=128)
    note: str = Field(default="", max_length=2000)


class RiskAcceptanceCreate(BaseModel):
    campaign_id: str | None = None
    remediation_id: str | None = None
    technique_id: str | None = None
    finding_title: str = Field(min_length=3, max_length=255)
    rationale: str = Field(min_length=20, max_length=4000)
    approver: str = Field(min_length=2, max_length=128)
    expires_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


class RiskAcceptanceResponse(RiskAcceptanceCreate):
    acceptance_id: str
    status: Literal["active", "expired", "revoked"]
    created_at: datetime
    updated_at: datetime


class CoverageScorecard(BaseModel):
    expected_techniques: int = Field(ge=0)
    detected_techniques: int = Field(ge=0)
    open_gaps: int = Field(ge=0)
    accepted_risks: int = Field(ge=0)
    coverage_percent: float = Field(ge=0, le=100)
    effective_coverage_percent: float = Field(ge=0, le=100)


class ExecutiveKpis(BaseModel):
    risk_score: float = Field(ge=0, le=100)
    detection_coverage_percent: float = Field(ge=0, le=100)
    effective_coverage_percent: float = Field(ge=0, le=100)
    open_critical_findings: int = Field(ge=0)
    overdue_remediations: int = Field(ge=0)
    expiring_acceptances: int = Field(ge=0)
    evidence_review_backlog: int = Field(ge=0)


class TrendPoint(BaseModel):
    period: str
    average_risk_score: float = Field(ge=0, le=100)
    average_coverage_percent: float = Field(ge=0, le=100)
    run_count: int = Field(ge=0)


class DetectionTuningItem(BaseModel):
    technique_id: str
    gap_count: int = Field(ge=0)
    priority: Literal["low", "medium", "high"]
    rule_intent: str
    event_sources: list[str] = Field(default_factory=list)
    regression_fixture: str


class IntegrityVerification(BaseModel):
    valid: bool
    event_count: int = Field(ge=0)
    tail_digest: str
    first_invalid_event_id: str | None = None
    error: str | None = None


class EvidenceManifest(BaseModel):
    evidence_id: str
    canonical_payload: str
    manifest_sha256: str
    generated_at: datetime


class RemediationSlaItem(BaseModel):
    remediation_id: str
    finding_title: str
    priority: str
    status: str
    owner: str
    due_date: str | None = None
    target_days: int = Field(ge=1)
    state: Literal["on_track", "due_soon", "overdue", "closed"]


class CampaignTimelineEvent(BaseModel):
    event_type: str
    reference_id: str
    title: str
    status: str
    occurred_at: datetime


class CampaignExport(BaseModel):
    campaign: CampaignResponse
    timeline: list[CampaignTimelineEvent] = Field(default_factory=list)
    evidence: list[EvidenceResponse] = Field(default_factory=list)
    remediations: list[RemediationResponse] = Field(default_factory=list)
    trend: list[TrendPoint] = Field(default_factory=list)
    detection_tuning: list[DetectionTuningItem] = Field(default_factory=list)
    manifest_sha256: str
    generated_at: datetime


class PurpleAnalysisRequest(BaseModel):
    expected_technique_ids: list[str] = Field(min_length=1)
    alerts: list[WazuhAlert] = Field(default_factory=list)
    dry_run: bool = True


class DetectionGapReport(BaseModel):
    run_id: str
    coverage_percent: float = Field(ge=0, le=100)
    observations: list[CoverageObservation]
    gaps: list[str]
    generated_at: datetime
