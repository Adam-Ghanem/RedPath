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
    duration_ms: int | None = Field(default=None, ge=0)
    recovery_count: int = Field(default=0, ge=0)
    attempt_count: int = Field(default=0, ge=0)
    retry_budget: int = Field(default=2, ge=0, le=5)
    retry_class: Literal["none", "transient", "permanent"] = "none"
    next_retry_at: datetime | None = None
    checkpoint_stage: str | None = Field(default=None, max_length=64)
    result_compacted: bool = False
    result_bytes: int | None = Field(default=None, ge=0, le=65536)


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


class RiskQueryBounds(BaseModel):
    """Effective limits reported for a bounded, read-only risk planning operation."""

    max_paths: int = Field(default=100, ge=1, le=500)
    max_traversal_steps: int = Field(default=10_000, ge=1, le=100_000)
    max_asset_ids: int = Field(default=200, ge=1, le=500)
    max_evidence_ids: int = Field(default=200, ge=1, le=500)


class RiskPathSnapshot(BaseModel):
    """Server-derived minimized path data; raw graph nodes and edges are not accepted."""

    model_config = ConfigDict(extra="forbid")

    path_id: str = Field(pattern=r"^path-[a-f0-9]{12}$")
    risk_score: float = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical"]
    centrality: float = Field(default=0.0, ge=0, le=1)
    rationale: str = Field(default="", max_length=512)
    technique_ids: list[str] = Field(default_factory=list, max_length=32)
    asset_ids: list[str] = Field(default_factory=list, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    hop_count: int = Field(ge=1, le=32)


class RiskGraphSnapshot(BaseModel):
    """Tenant-authoritative, minimized snapshot used for offline policy simulation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["risk-snapshot.v1"] = "risk-snapshot.v1"
    tenant_id: str = Field(min_length=1, max_length=128)
    analysis_id: str = Field(min_length=1, max_length=128)
    graph_fingerprint: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    paths: list[RiskPathSnapshot] = Field(max_length=500)


class RiskPolicySimulationRequest(BaseModel):
    """Client policy knobs only; the server resolves the graph snapshot by analysis_id."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=128)
    blocked_technique_ids: list[str] = Field(default_factory=list, max_length=32)
    max_paths: int = Field(default=100, ge=1, le=500)
    max_traversal_steps: int = Field(default=10_000, ge=1, le=100_000)

    @field_validator("blocked_technique_ids")
    @classmethod
    def validate_technique_ids(cls, values: list[str]) -> list[str]:
        normalized = sorted(set(values))
        if any(not value.startswith("T") or len(value) > 32 for value in normalized):
            raise ValueError("blocked technique IDs must be bounded MITRE-style identifiers")
        return normalized


class RiskScoreDiff(BaseModel):
    path_id: str
    baseline_score: float = Field(ge=0, le=100)
    simulated_score: float = Field(ge=0, le=100)
    delta: float = Field(ge=-100, le=100)
    baseline_level: Literal["low", "medium", "high", "critical"]
    simulated_level: Literal["low", "medium", "high", "critical"]
    blocked_by_technique_ids: list[str] = Field(default_factory=list, max_length=32)


class RiskBlastRadiusSummary(BaseModel):
    affected_path_count: int = Field(ge=0)
    affected_asset_ids: list[str] = Field(default_factory=list, max_length=200)
    affected_evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    baseline_score: float = Field(ge=0, le=100)
    simulated_score: float = Field(ge=0, le=100)
    score_delta: float = Field(ge=-100, le=100)


class RiskQueryCost(BaseModel):
    paths_considered: int = Field(ge=0)
    traversal_steps: int = Field(ge=0)
    truncated: bool = False
    duration_ms: int = Field(ge=0, le=60_000)
    bounds: RiskQueryBounds


class RiskCacheInvalidationEvent(BaseModel):
    """Read-only cache invalidation contract; no remote or database mutation is implied."""

    schema_version: Literal["risk-cache.v1"] = "risk-cache.v1"
    tenant_id: str = Field(min_length=1, max_length=128)
    analysis_id: str = Field(min_length=1, max_length=128)
    graph_fingerprint: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    reason: Literal["snapshot_changed", "policy_catalog_changed", "manual_review"]
    invalidation_key: str = Field(min_length=16, max_length=128)


class RiskPolicySimulationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["risk-simulation.v1"] = "risk-simulation.v1"
    tenant_id: str
    analysis_id: str
    graph_fingerprint: str
    blocked_technique_ids: list[str] = Field(default_factory=list, max_length=32)
    score_diffs: list[RiskScoreDiff] = Field(default_factory=list, max_length=500)
    blast_radius: RiskBlastRadiusSummary
    query_cost: RiskQueryCost
    cache_key: str = Field(min_length=16, max_length=128)
    cache_hit: bool = False


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

    schema_version: Literal["1.0"] = "1.0"
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
    telemetry_requirements: list[str] = Field(default_factory=list, max_length=16)
    coverage_type: Literal["prevention", "detection", "response"] = "detection"
    mttd_target_seconds: int = Field(default=900, ge=1, le=86400)
    owner: str = Field(default="", max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=16)
    deployment_status: Literal["draft", "testing", "production"] = "testing"
    approval_state: Literal["not_required", "pending", "approved", "rejected"] = "pending"
    reviewed_by: str | None = Field(default=None, max_length=128)
    reviewed_at: datetime | None = None
    deprecation_status: Literal["active", "scheduled", "deprecated"] = "active"
    deprecation_sunset_at: datetime | None = None
    replacement_rule_id: str | None = Field(default=None, max_length=128)
    deprecation_reason: str = Field(default="", max_length=1000)
    requires_approval: bool = True


class DetectionRuleCreate(DetectionRule):
    pass


class DetectionRuleValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    version: int = Field(ge=1)
    valid: bool
    mitre_valid: bool
    safe_logic: bool
    approval_valid: bool
    errors: list[str] = Field(default_factory=list, max_length=32)
    warnings: list[str] = Field(default_factory=list, max_length=32)


def _quality_timestamp(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        raise ValueError("quality-operation timestamps must be timezone-aware")
    return value


class TuningProposalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    rule_version: int = Field(ge=1)
    proposal_type: Literal["reduce_false_positives", "improve_coverage", "threshold_review", "deprecate_rule"]
    summary: str = Field(min_length=10, max_length=2000)
    rationale: str = Field(min_length=10, max_length=4000)
    evidence_fixture_ids: list[str] = Field(default_factory=list, max_length=64)
    target_false_positive_rate: float | None = Field(default=None, ge=0, le=100)
    proposed_window_seconds: int | None = Field(default=None, ge=1, le=86400)
    proposed_sunset_at: datetime | None = None
    replacement_rule_id: str | None = Field(default=None, max_length=128)

    _sunset_timezone = field_validator("proposed_sunset_at")(_quality_timestamp)


class FalsePositiveReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    rule_version: int = Field(ge=1)
    classification: Literal["false_positive", "benign_expected", "duplicate", "needs_investigation"]
    reason_code: Literal[
        "authorized_activity",
        "expected_automation",
        "telemetry_quality",
        "duplicate_signal",
        "insufficient_context",
    ]
    analyst_note: str = Field(min_length=10, max_length=2000)
    evidence_fixture_id: str | None = Field(default=None, max_length=128)


class FalsePositiveReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: str
    tenant_id: str
    alert_id: str
    rule_id: str
    rule_version: int
    classification: Literal["false_positive", "benign_expected", "duplicate", "needs_investigation"]
    reason_code: str
    analyst_note: str
    evidence_fixture_id: str | None = None
    reviewed_by: str
    reviewed_at: datetime


class TuningProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    tenant_id: str
    rule_id: str
    rule_version: int
    proposal_type: Literal["reduce_false_positives", "improve_coverage", "threshold_review", "deprecate_rule"]
    summary: str
    rationale: str
    evidence_fixture_ids: list[str] = Field(default_factory=list, max_length=64)
    target_false_positive_rate: float | None = Field(default=None, ge=0, le=100)
    proposed_window_seconds: int | None = Field(default=None, ge=1, le=86400)
    proposed_sunset_at: datetime | None = None
    replacement_rule_id: str | None = None
    status: Literal["proposed", "approved", "rejected"]
    created_by: str
    created_at: datetime
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None


class TuningProposalReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    review_note: str = Field(min_length=10, max_length=2000)


class DetectionQualitySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    captured_at: datetime
    rule_count: int = Field(ge=0, le=10000)

    _captured_at_timezone = field_validator("captured_at")(_quality_timestamp)
    coverage_percent: float = Field(ge=0, le=100)
    path_coverage_percent: float = Field(ge=0, le=100)
    true_positive_rate: float = Field(ge=0, le=100)
    false_positive_rate: float = Field(ge=0, le=100)
    rule_provenance: list[DetectionRuleProvenance] = Field(default_factory=list, max_length=128)


class CoverageDriftThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_coverage_drop_percent: float = Field(default=5.0, ge=0, le=100)
    max_path_coverage_drop_percent: float = Field(default=5.0, ge=0, le=100)
    max_true_positive_drop_percent: float = Field(default=5.0, ge=0, le=100)
    max_false_positive_increase_percent: float = Field(default=5.0, ge=0, le=100)


class CoverageDriftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline: DetectionQualitySnapshot
    current: DetectionQualitySnapshot
    thresholds: CoverageDriftThresholds = Field(default_factory=CoverageDriftThresholds)


class CoverageDriftReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    baseline_snapshot_id: str
    current_snapshot_id: str
    coverage_delta_percent: float
    path_coverage_delta_percent: float
    true_positive_delta_percent: float
    false_positive_delta_percent: float
    drift_detected: bool
    drift_reasons: list[str] = Field(default_factory=list, max_length=16)
    rationale: str = Field(min_length=1, max_length=2000)


class RegressionTrendPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=128)
    captured_at: datetime
    total_cases: int = Field(ge=0, le=10000)

    _captured_at_timezone = field_validator("captured_at")(_quality_timestamp)
    passed_cases: int = Field(ge=0, le=10000)
    true_positive_rate: float = Field(ge=0, le=100)
    false_positive_rate: float = Field(ge=0, le=100)
    coverage_percent: float = Field(ge=0, le=100)


class RegressionTrendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    points: list[RegressionTrendPoint] = Field(min_length=1, max_length=90)


class RegressionTrendReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    points: list[RegressionTrendPoint]
    true_positive_delta_percent: float
    false_positive_delta_percent: float
    coverage_delta_percent: float
    direction: Literal["improving", "stable", "degrading"]
    rationale: str = Field(min_length=1, max_length=2000)


class RuleDeprecationWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_version: int
    status: Literal["active", "scheduled", "deprecated"]
    sunset_at: datetime | None = None
    days_remaining: int | None = None
    replacement_rule_id: str | None = None
    rationale: str


class RuleDeprecationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    windows: list[RuleDeprecationWindow] = Field(default_factory=list, max_length=128)
    warnings: list[str] = Field(default_factory=list, max_length=32)


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


class DetectionBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_true_positive_rate: float = Field(default=100.0, ge=0, le=100)
    max_false_positive_rate: float = Field(default=5.0, ge=0, le=100)
    min_rule_coverage_percent: float = Field(default=100.0, ge=0, le=100)
    min_path_coverage_percent: float = Field(default=0.0, ge=0, le=100)


class DetectionPackRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    version: int = Field(ge=1)
    fixture_ids: list[str] = Field(min_length=1, max_length=128)


class DetectionPackManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    pack_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    pack_version: int = Field(ge=1, le=10_000)
    owner: str = Field(min_length=1, max_length=128)
    rules: list[DetectionPackRule] = Field(min_length=1, max_length=128)
    baseline: DetectionBaseline = Field(default_factory=DetectionBaseline)


class DetectionLifecycleGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack: DetectionPackManifest
    fixtures: list[NormalizedRegressionFixture] = Field(min_length=1, max_length=256)
    rule_ids: list[str] = Field(default_factory=list, max_length=128)
    dry_run: bool = True


class DetectionLifecycleGateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gate_id: str
    pack_id: str
    pack_version: int
    pack_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    tenant_id: str
    actor: str
    status: Literal["passed", "failed", "blocked"]
    validation: list[DetectionRuleValidationResult] = Field(default_factory=list)
    regression_report: NormalizedRegressionReport | None = None
    coverage_report: DetectionCoverageReport | None = None
    baseline: DetectionBaseline
    observed_true_positive_rate: float = Field(default=0.0, ge=0, le=100)
    observed_false_positive_rate: float = Field(default=0.0, ge=0, le=100)
    observed_rule_coverage_percent: float = Field(default=0.0, ge=0, le=100)
    observed_path_coverage_percent: float = Field(default=0.0, ge=0, le=100)
    errors: list[str] = Field(default_factory=list, max_length=64)
    warnings: list[str] = Field(default_factory=list, max_length=64)
    dry_run: bool


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
    custody_status: Literal["unverified", "verified", "rejected"] = "unverified"
    custody_verified_by: str | None = None
    custody_verified_at: datetime | None = None
    custody_verification_sha256: str | None = None
    created_at: datetime


class EvidenceReviewUpdate(BaseModel):
    review_status: Literal["unreviewed", "in_review", "accepted", "rejected"]
    notes: str = Field(default="", max_length=4000)


class EvidenceCustodyVerifyRequest(BaseModel):
    decision: Literal["verified", "rejected"]
    manifest_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    note: str = Field(default="", max_length=2000)


class EvidenceCustodyEventResponse(BaseModel):
    event_id: str
    tenant_id: str
    case_id: str
    evidence_id: str
    decision: Literal["verified", "rejected"]
    actor: str
    manifest_sha256: str
    note: str = ""
    created_at: datetime


class EvidenceIntegrityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    tenant_id: str
    valid: bool
    checked_at: datetime
    expected_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stored_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    storage_backend: str = Field(min_length=1, max_length=32)
    raw_bytes_retained: bool = False
    stored_bytes: int = Field(default=0, ge=0)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_code: str | None = None


class EvidenceLegalHoldRequest(BaseModel):
    action: Literal["place", "release"]
    reason: str = Field(min_length=3, max_length=2000)


class EvidenceLegalHoldResponse(BaseModel):
    evidence_id: str
    tenant_id: str
    active: bool
    reason: str = ""
    placed_by: str | None = None
    placed_at: datetime | None = None
    released_by: str | None = None
    released_at: datetime | None = None
    updated_at: datetime


class EvidenceRetentionDecisionRequest(BaseModel):
    decision: Literal["retain", "eligible_for_deletion", "defer"]
    reason: str = Field(min_length=3, max_length=2000)


class EvidenceRetentionDecisionResponse(BaseModel):
    decision_id: str
    evidence_id: str
    tenant_id: str
    decision: Literal["retain", "eligible_for_deletion", "defer"]
    reason: str
    actor: str
    created_at: datetime


class EvidenceDeletionRequestCreate(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class EvidenceDeletionDecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=2000)


class EvidenceDeletionRequestResponse(BaseModel):
    request_id: str
    evidence_id: str
    tenant_id: str
    state: Literal["requested", "approved", "rejected"]
    reason: str
    requested_by: str
    requested_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_note: str = ""


class EvidenceStorageMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storage_backend: Literal["metadata-only"] = "metadata-only"
    storage_locator: Literal["none"] = "none"
    raw_bytes_retained: Literal[False] = False
    stored_bytes: int = Field(default=0, ge=0, le=0)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvidencePrivacySummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    tenant_id: str
    evidence_type: str
    review_status: str
    custody_status: Literal["unverified", "verified", "rejected"]
    legal_hold: bool
    retention_decision: Literal["retain", "eligible_for_deletion", "defer"] | None = None
    deletion_request_state: Literal["requested", "approved", "rejected"] | None = None
    manifest_verified: bool
    storage: EvidenceStorageMetadata
    summary: str = Field(max_length=500)
    created_at: datetime


class RemediationCreate(BaseModel):
    campaign_id: str | None = None
    finding_title: str = Field(min_length=3, max_length=255)
    technique_id: str | None = None
    recommendation: str = Field(min_length=10, max_length=4000)
    owner: str = Field(default="unassigned", min_length=2, max_length=128)
    assigned_to: str | None = Field(default=None, min_length=2, max_length=128)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    due_date: str | None = None


class RemediationResponse(RemediationCreate):
    tenant_id: str
    remediation_id: str
    status: str
    verification_status: Literal["unverified", "pending", "verified", "rejected"] = "unverified"
    verified_by: str | None = None
    verified_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RemediationLifecycleUpdate(BaseModel):
    status: Literal["open", "in_progress", "blocked", "resolved", "closed"]
    note: str = Field(default="", max_length=2000)


class RemediationAssignmentUpdate(BaseModel):
    assigned_to: str = Field(min_length=2, max_length=128)


class RemediationVerificationUpdate(BaseModel):
    decision: Literal["verified", "rejected"]
    note: str = Field(default="", max_length=2000)
    evidence_id: str | None = Field(default=None, min_length=1, max_length=36)
    manifest_sha256: str | None = Field(default=None, min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")


class RemediationVerificationEvidenceRequest(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=36)
    manifest_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    summary: str = Field(default="", max_length=2000)


class RemediationVerificationEvidenceResponse(BaseModel):
    evidence_record_id: str
    tenant_id: str
    case_id: str | None = None
    remediation_id: str
    evidence_id: str
    manifest_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    summary: str = ""
    recorded_by: str
    created_at: datetime


class ApprovalDelegationCreate(BaseModel):
    campaign_id: str | None = None
    delegate_username: str = Field(min_length=2, max_length=128)
    starts_at: datetime | None = None
    expires_at: datetime


class ApprovalDelegationResponse(BaseModel):
    delegation_id: str
    tenant_id: str
    campaign_id: str | None = None
    delegator_username: str
    delegate_username: str
    starts_at: datetime
    expires_at: datetime
    status: Literal["active", "expired", "revoked"]
    created_by: str
    revoked_by: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RemediationEscalationDraft(BaseModel):
    draft_id: str
    tenant_id: str
    remediation_id: str
    recipient_actor: str
    state: Literal["due_soon", "overdue"]
    escalation_level: Literal["manager_review", "leadership_review"]
    policy_version: Literal["2.0"] = "2.0"
    notification_mode: Literal["mock"] = "mock"
    requires_opt_in: bool = True
    sent: bool = False
    subject: str
    body: str
    generated_at: datetime


class RiskAcceptanceExpiryReminder(BaseModel):
    reminder_id: str
    tenant_id: str
    acceptance_id: str
    approver: str
    expires_on: str
    days_remaining: int
    urgency: Literal["expiring", "expired"]
    policy_version: Literal["1.0"] = "1.0"
    notification_mode: Literal["mock"] = "mock"
    requires_opt_in: bool = True
    sent: bool = False
    generated_at: datetime


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
    delegation_id: str | None = None
    delegated_from: str | None = None
    status: Literal["active", "expired", "revoked"]
    approval_status: Literal["approved", "revoked", "expired"] = "approved"
    approved_by: str | None = None
    approved_at: datetime | None = None
    revoked_by: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RiskAcceptanceDecisionRequest(BaseModel):
    decision: Literal["approve", "revoke"]
    expires_on: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    note: str = Field(default="", max_length=2000)
    delegation_id: str | None = Field(default=None, min_length=1, max_length=36)


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


class SlaClock(BaseModel):
    policy_version: Literal["2.0"] = "2.0"
    started_at: datetime
    due_at: datetime
    elapsed_seconds: int = Field(ge=0)
    remaining_seconds: int
    paused_seconds: int = Field(ge=0)
    state: Literal["on_track", "due_soon", "overdue", "closed"]


class RemediationSlaItem(BaseModel):
    remediation_id: str
    finding_title: str
    priority: str
    status: str
    owner: str
    assigned_to: str | None = None
    due_date: str | None = None
    target_days: int = Field(ge=1)
    state: Literal["on_track", "due_soon", "overdue", "closed"]
    clock: SlaClock


class RemediationSlaEscalation(BaseModel):
    tenant_id: str
    remediation_id: str
    assigned_to: str | None = None
    state: Literal["due_soon", "overdue"]
    escalation_level: Literal["manager_review", "leadership_review"]
    policy_version: Literal["2.0"] = "2.0"
    recommended_action: str
    draft_id: str
    notification_mode: Literal["mock"] = "mock"
    requires_opt_in: bool = True


class CampaignTimelineEvent(BaseModel):
    event_type: str
    reference_id: str
    title: str
    status: str
    occurred_at: datetime


class CaseDecisionEventResponse(BaseModel):
    event_id: str
    tenant_id: str
    case_id: str
    resource_type: str
    resource_id: str
    decision_type: str
    actor: str
    previous_state: str | None = None
    new_state: str | None = None
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    previous_digest: str
    digest: str
    created_at: datetime


class CaseDecisionTimelineResponse(BaseModel):
    case_id: str
    tenant_id: str
    events: list[CaseDecisionEventResponse] = Field(default_factory=list)
    integrity_valid: bool
    tail_digest: str


class CampaignExport(BaseModel):
    schema_version: Literal["case-export.v3"] = "case-export.v3"
    tenant_id: str
    actor: str
    campaign: CampaignResponse
    timeline: list[CampaignTimelineEvent] = Field(default_factory=list)
    evidence: list[EvidenceResponse] = Field(default_factory=list)
    remediations: list[RemediationResponse] = Field(default_factory=list)
    verification_evidence: list[RemediationVerificationEvidenceResponse] = Field(default_factory=list)
    custody_history: list[EvidenceCustodyEventResponse] = Field(default_factory=list)
    governance_history: list[GovernanceHistoryEvent] = Field(default_factory=list)
    risk_acceptances: list[RiskAcceptanceResponse] = Field(default_factory=list)
    sla_escalations: list[RemediationSlaEscalation] = Field(default_factory=list)
    trend: list[TrendPoint] = Field(default_factory=list)
    detection_tuning: list[DetectionTuningItem] = Field(default_factory=list)
    manifest_sha256: str
    generated_at: datetime
    decision_timeline: list["CaseDecisionEventResponse"] = Field(default_factory=list)
    timeline_integrity: bool = True
    export_policy_version: Literal["2.0"] = "2.0"


class CaseExportFixture(BaseModel):
    fixture_version: Literal["1.0"] = "1.0"
    tenant_id: str
    actor: str
    case_id: str
    source_manifest_sha256: str
    record_counts: dict[str, int] = Field(default_factory=dict)
    timeline_integrity: bool
    redacted: Literal[True] = True
    fixture_sha256: str
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
