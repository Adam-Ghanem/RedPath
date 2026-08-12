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


class AttackEdge(BaseModel):
    source: str
    target: str
    technique_id: str | None = None
    weight: float = Field(default=1.0, gt=0)
    rationale: str = ""


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
