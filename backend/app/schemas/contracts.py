from __future__ import annotations

from datetime import datetime
from string import hexdigits
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from app.models.domain import Asset as SharedAsset
from app.models.telemetry import TelemetryEvent


class DiscoveryJobCreate(BaseModel):
    """Request to enqueue a bounded, allow-listed discovery job."""

    targets: list[IPvAnyAddress] = Field(min_length=1, max_length=64)
    profile: Literal["safe", "service_inventory"] = "safe"
    dry_run: bool = True


class DiscoveryJobStatus(BaseModel):
    """Persisted state for an asynchronous discovery job."""

    job_id: str
    tenant_id: str
    status: Literal["queued", "running", "completed", "failed"]
    profile: Literal["safe", "service_inventory"]
    dry_run: bool
    targets: list[str]
    scan_id: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    progress_percent: int = Field(default=0, ge=0, le=100)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AssetProvenance(BaseModel):
    """Bounded provenance attached to a normalized inventory observation."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=128)
    scan_id: str = Field(min_length=1, max_length=128)
    job_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    observed_at: datetime
    dry_run: bool
    observation_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class InventoryAsset(BaseModel):
    """Shared asset identity plus normalized, tenant-scoped discovery observations."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    asset: SharedAsset
    asset_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    asset_type: Literal["host"] = "host"
    ip: str
    hostname: str | None = None
    ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    scan_id: str
    source: str = "recon"
    discovered_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    provenance: AssetProvenance


class ReconRequest(BaseModel):
    targets: list[IPvAnyAddress] = Field(min_length=1, max_length=64)
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
    asset_id: str | None = Field(default=None, min_length=1, max_length=128)


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
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)


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
    asset_ids: list[str] = Field(default_factory=list, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    remediation_priority: Literal["low", "medium", "high", "critical"] = "medium"
    remediation_rationale: str = Field(default="", max_length=2000)


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
    asset_ids: list[str] = Field(default_factory=list, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    remediation_priority: Literal["low", "medium", "high", "critical"] = "medium"
    remediation_ids: list[str] = Field(default_factory=list, max_length=200)
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
    asset_id: str | None = Field(default=None, max_length=128)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    remediation_priority: Literal["low", "medium", "high", "critical"] = "medium"


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
    analysis_id: str
    graph_fingerprint: str
    graph_summary: GraphSummary
    entry_points: list[str]
    crown_jewel_nodes: list[str]
    ranked_paths: list[RankedAttackPath]
    choke_points: list[ChokePoint]
    cloud_paths: list[str]
    unreachable_crown_jewels: list[str]
    asset_ids: list[str] = Field(default_factory=list, max_length=500)
    evidence_ids: list[str] = Field(default_factory=list, max_length=500)
    remediation_priorities: dict[str, str] = Field(default_factory=dict, max_length=500)
    remediation_links: list["AttackPathRemediationLink"] = Field(default_factory=list, max_length=500)
    warnings: list[str] = Field(default_factory=list)


class AttackPathRemediationLink(BaseModel):
    """Stable, tenant-scoped link ready for persistence or remediation queue creation."""

    schema_version: Literal["1.0"] = "1.0"
    remediation_link_id: str
    analysis_id: str
    tenant_id: str
    path_id: str
    asset_ids: list[str] = Field(default_factory=list, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    priority: Literal["low", "medium", "high", "critical"]
    rationale: str = Field(min_length=1, max_length=2000)


class CopilotDetectionEvidence(BaseModel):
    """Bounded evidence fields permitted in a grounded explanation request."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=128)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    technique_id: str | None = Field(default=None, max_length=32, pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    signal: str = Field(default="", max_length=512)


class CopilotAttackPathSummary(BaseModel):
    """Minimized attack-path context; raw graph nodes and edges are not accepted."""

    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0, le=100)
    centrality: float = Field(default=0.0, ge=0, le=1)
    hop_count: int = Field(default=0, ge=0, le=12)
    asset_count: int = Field(default=0, ge=0, le=50)
    evidence_count: int = Field(default=0, ge=0, le=50)
    asset_ids: list[str] = Field(default_factory=list, max_length=50)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    technique_ids: list[str] = Field(default_factory=list, max_length=32)
    rationale: str = Field(default="", max_length=512)


class CopilotExplainRequest(BaseModel):
    """Identifier-only client request; all score and evidence context is server-resolved."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str | None = Field(default=None, min_length=1, max_length=128)
    analysis_id: str | None = Field(default=None, min_length=1, max_length=128)
    path_id: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_source_reference(self) -> "CopilotExplainRequest":
        finding_only = bool(self.finding_id) and not self.analysis_id and not self.path_id
        path_only = bool(self.analysis_id and self.path_id) and not self.finding_id
        if not (finding_only or path_only):
            raise ValueError("request must contain only finding_id or analysis_id plus path_id")
        return self

    @property
    def source_type(self) -> Literal["finding", "attack_path"]:
        return "finding" if self.finding_id else "attack_path"


class CopilotResolvedContext(BaseModel):
    """Server-derived deterministic source context; never accepted directly from clients."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    source_type: Literal["finding", "attack_path"]
    source_id: str = Field(min_length=1, max_length=128)
    deterministic_score: float = Field(ge=0, le=100)
    centrality: float = Field(default=0.0, ge=0, le=1)
    deterministic_tier: Literal["low", "medium", "high", "critical"]
    attack_path: CopilotAttackPathSummary | None = None
    evidence: list[CopilotDetectionEvidence] = Field(default_factory=list, max_length=8)


class CopilotProviderOutput(BaseModel):
    """Strict provider response; deterministic tier is never provider-controlled."""

    model_config = ConfigDict(extra="forbid")

    explanation: str = Field(min_length=1, max_length=1200)
    next_actions: list[str] = Field(min_length=1, max_length=2)
    confidence_note: str = Field(min_length=1, max_length=512)


class CopilotExplanationResponse(BaseModel):
    """Grounded explanation with explicit deterministic or non-AI fallback status."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: str = Field(min_length=1, max_length=128)
    subject_type: Literal["finding", "attack_path"]
    subject_id: str = Field(min_length=1, max_length=128)
    deterministic_score: float = Field(ge=0, le=100)
    deterministic_tier: Literal["low", "medium", "high", "critical"]
    tier: Literal["low", "medium", "high", "critical"]
    explanation: str = Field(min_length=1, max_length=1200)
    next_actions: list[str] = Field(min_length=1, max_length=2)
    confidence_note: str = Field(min_length=1, max_length=512)
    ai_status: Literal["disabled", "fallback", "generated"]
    fallback_reason: Literal[
        "none",
        "ai_disabled",
        "provider_unavailable",
        "provider_timeout",
        "provider_rate_limited",
        "provider_error",
        "provider_invalid_output",
    ] = "none"
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    data_egress: Literal["none", "sanitized_context_only"]
    cache_hit: bool = False


class AttackPathAnalysisRecord(BaseModel):
    """Persistence-ready aggregate; actor identity is supplied by the server boundary."""

    schema_version: Literal["1.0"] = "1.0"
    analysis_id: str
    tenant_id: str
    actor_id: str
    graph_fingerprint: str
    path_ids: list[str] = Field(default_factory=list, max_length=500)
    asset_ids: list[str] = Field(default_factory=list, max_length=500)
    evidence_ids: list[str] = Field(default_factory=list, max_length=500)
    remediation_links: list[AttackPathRemediationLink] = Field(default_factory=list, max_length=500)
    created_at: datetime


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


class DetectionCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    operator: Literal["equals", "contains", "starts_with", "in"]
    value: Any


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    version: int = Field(default=1, ge=1, le=10_000)
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=10, max_length=2000)
    technique_ids: list[str] = Field(min_length=1, max_length=8)
    severity: Literal["info", "low", "medium", "high", "critical"]
    event_sources: list[str] = Field(min_length=1, max_length=8)
    conditions: list[DetectionCondition] = Field(min_length=1, max_length=10)
    match_mode: Literal["all", "any"] = "all"
    window_seconds: int = Field(default=300, ge=1, le=86400)
    group_by: list[str] = Field(default_factory=list, max_length=3)
    enabled: bool = True
    false_positive_sla_percent: float = Field(default=5.0, ge=0, le=100)
    deployment_status: Literal["draft", "testing", "production"] = "testing"
    requires_approval: bool = True


class DetectionRuleCreate(DetectionRule):
    pass


class DetectionRuleProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    version: int = Field(ge=1)
    source: Literal["builtin", "registered"]
    content_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    deployment_status: Literal["draft", "testing", "production"]
    requires_approval: bool


class DetectionMatch(BaseModel):
    rule_id: str
    rule_version: int = Field(default=1, ge=1)
    technique_ids: list[str]
    alert_ids: list[str]
    matched_condition_count: int = Field(ge=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    group_key: str = "all-events"
    rationale: str
    provenance_sha256: str | None = Field(default=None, min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    path_evidence_ids: list[str] = Field(default_factory=list, max_length=100)


class DetectionEvaluationRequest(BaseModel):
    events: list[WazuhAlert] = Field(min_length=1, max_length=10000)
    rule_ids: list[str] = Field(default_factory=list, max_length=128)


class DetectionEvaluationResponse(BaseModel):
    evaluated_at: datetime
    event_count: int = Field(ge=0)
    rule_count: int = Field(ge=0)
    matches: list[DetectionMatch] = Field(default_factory=list)
    tenant_id: str | None = Field(default=None, max_length=128)
    actor: str | None = Field(default=None, max_length=128)
    rule_provenance: list[DetectionRuleProvenance] = Field(default_factory=list, max_length=128)


class RegressionFixture(BaseModel):
    fixture_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    title: str = Field(min_length=3, max_length=255)
    rule_id: str
    expected_match: bool
    events: list[WazuhAlert] = Field(min_length=1, max_length=10000)
    description: str = Field(default="", max_length=2000)


class RegressionRunRequest(BaseModel):
    fixtures: list[RegressionFixture] | None = Field(default=None, max_length=256)
    rule_ids: list[str] = Field(default_factory=list, max_length=128)


class RegressionCaseResult(BaseModel):
    fixture_id: str
    rule_id: str
    expected_match: bool
    actual_match: bool
    passed: bool
    alert_ids: list[str] = Field(default_factory=list)
    notes: str


class RegressionReport(BaseModel):
    run_id: str
    status: Literal["passed", "failed"]
    total_cases: int = Field(ge=0)
    passed_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    true_positive_rate: float = Field(ge=0, le=100)
    false_positive_rate: float = Field(ge=0, le=100)
    cases: list[RegressionCaseResult] = Field(default_factory=list)
    generated_at: datetime
    tenant_id: str | None = Field(default=None, max_length=128)
    actor: str | None = Field(default=None, max_length=128)
    rule_provenance: list[DetectionRuleProvenance] = Field(default_factory=list, max_length=128)


class AttackPathEvidence(BaseModel):
    """A bounded projection of analyzed attack-path evidence; raw graph payloads are not accepted here."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    path_id: str = Field(pattern=r"^path-[a-f0-9]{12}$")
    risk_score: float = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical"]
    technique_ids: list[str] = Field(default_factory=list, max_length=16)
    asset_ids: list[str] = Field(default_factory=list, max_length=128)
    summary: str = Field(min_length=1, max_length=2000)
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def evidence_timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("attack-path evidence timestamp must be timezone-aware")
        return value


class DetectionCoverageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    telemetry: list[TelemetryEvent] = Field(default_factory=list, max_length=10000)
    rule_ids: list[str] = Field(default_factory=list, max_length=128)
    attack_paths: list[AttackPathEvidence] = Field(default_factory=list, max_length=500)
    dry_run: bool = True


class DetectionCoverageObservation(BaseModel):
    rule_id: str
    rule_version: int = Field(ge=1)
    technique_ids: list[str] = Field(default_factory=list)
    detected: bool = False
    evidence_count: int = Field(ge=0)
    telemetry_event_ids: list[str] = Field(default_factory=list)
    path_evidence_ids: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1, max_length=4000)
    recommendation: str = ""


class DetectionCoverageReport(BaseModel):
    run_id: str
    tenant_id: str
    actor: str
    evaluated_at: datetime
    expected_rule_count: int = Field(ge=0)
    detected_rule_count: int = Field(ge=0)
    coverage_percent: float = Field(ge=0, le=100)
    path_count: int = Field(ge=0)
    covered_path_count: int = Field(ge=0)
    path_coverage_percent: float = Field(ge=0, le=100)
    observations: list[DetectionCoverageObservation] = Field(default_factory=list)
    path_evidence_ids: list[str] = Field(default_factory=list)
    rule_provenance: list[DetectionRuleProvenance] = Field(default_factory=list)
    dry_run: bool
    warnings: list[str] = Field(default_factory=list)


class NormalizedRegressionFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    title: str = Field(min_length=3, max_length=255)
    rule_id: str
    expected_match: bool
    telemetry: list[TelemetryEvent] = Field(min_length=1, max_length=10000)
    attack_paths: list[AttackPathEvidence] = Field(default_factory=list, max_length=500)
    description: str = Field(default="", max_length=2000)


class NormalizedRegressionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixtures: list[NormalizedRegressionFixture] = Field(min_length=1, max_length=256)
    rule_ids: list[str] = Field(default_factory=list, max_length=128)
    dry_run: bool = True


class NormalizedRegressionCaseResult(BaseModel):
    fixture_id: str
    rule_id: str
    expected_match: bool
    actual_match: bool
    passed: bool
    telemetry_event_ids: list[str] = Field(default_factory=list)
    path_evidence_ids: list[str] = Field(default_factory=list)
    notes: str


class NormalizedRegressionReport(BaseModel):
    run_id: str
    status: Literal["passed", "failed"]
    tenant_id: str
    actor: str
    total_cases: int = Field(ge=0)
    passed_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    true_positive_rate: float = Field(ge=0, le=100)
    false_positive_rate: float = Field(ge=0, le=100)
    cases: list[NormalizedRegressionCaseResult] = Field(default_factory=list)
    rule_provenance: list[DetectionRuleProvenance] = Field(default_factory=list)
    generated_at: datetime
    dry_run: bool
    warnings: list[str] = Field(default_factory=list)


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
    scope_snapshot: list[str] = Field(default_factory=list)


class CampaignResponse(CampaignCreate):
    tenant_id: str
    owner: str
    campaign_id: str
    status: str
    created_at: datetime
    updated_at: datetime


class CaseStatusUpdate(BaseModel):
    status: Literal["active", "on_hold", "closed"]
    note: str = Field(default="", max_length=2000)


class GovernanceHistoryEvent(BaseModel):
    event_id: str
    tenant_id: str
    case_id: str
    event_type: str
    actor: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class EvidenceCreate(BaseModel):
    campaign_id: str | None = None
    run_id: str | None = None
    evidence_type: str = Field(min_length=2, max_length=64)
    source: str = Field(min_length=2, max_length=255)
    title: str = Field(min_length=3, max_length=255)
    sha256: str = Field(min_length=64, max_length=64)
    technique_id: str | None = None
    notes: str = Field(default="", max_length=4000)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if any(character not in hexdigits for character in value):
            raise ValueError("sha256 must contain only hexadecimal characters")
        return value.lower()


class EvidenceResponse(EvidenceCreate):
    tenant_id: str
    evidence_id: str
    manifest_sha256: str
    review_status: str
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime


class EvidenceReviewUpdate(BaseModel):
    review_status: Literal["unreviewed", "in_review", "accepted", "rejected"]
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
    tenant_id: str
    remediation_id: str
    status: str
    created_at: datetime
    updated_at: datetime


class RemediationLifecycleUpdate(BaseModel):
    status: Literal["open", "in_progress", "blocked", "resolved", "closed"]
    note: str = Field(default="", max_length=2000)


class RiskAcceptanceCreate(BaseModel):
    campaign_id: str | None = None
    remediation_id: str | None = None
    technique_id: str | None = None
    finding_title: str = Field(min_length=3, max_length=255)
    rationale: str = Field(min_length=20, max_length=4000)
    expires_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


class RiskAcceptanceResponse(RiskAcceptanceCreate):
    tenant_id: str
    approver: str
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
    tenant_id: str
    campaign: CampaignResponse
    timeline: list[CampaignTimelineEvent] = Field(default_factory=list)
    evidence: list[EvidenceResponse] = Field(default_factory=list)
    remediations: list[RemediationResponse] = Field(default_factory=list)
    governance_history: list[GovernanceHistoryEvent] = Field(default_factory=list)
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
