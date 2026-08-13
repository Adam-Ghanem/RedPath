from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(32), default="recon")
    dry_run: Mapped[bool] = mapped_column(default=True)
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assets: Mapped[list["Asset"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ports: Mapped[list[int]] = mapped_column(JSON, default=list)
    services: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    scan_run: Mapped[ScanRun] = relationship(back_populates="assets")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    label: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))
    criticality: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    rationale: Mapped[str] = mapped_column(Text, default="")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    objective: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(128), default="security-team")
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    scope_snapshot: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CampaignRunLink(Base):
    __tablename__ = "campaign_run_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("assessment_runs.id"), nullable=True, index=True)
    evidence_type: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    review_status: Mapped[str] = mapped_column(String(32), default="unreviewed", index=True)
    reviewer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationItem(Base):
    __tablename__ = "remediation_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    finding_title: Mapped[str] = mapped_column(String(255))
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    recommendation: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(128), default="unassigned")
    priority: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    remediation_id: Mapped[str | None] = mapped_column(ForeignKey("remediation_items.id"), nullable=True, index=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    finding_title: Mapped[str] = mapped_column(String(255))
    rationale: Mapped[str] = mapped_column(Text)
    approver: Mapped[str] = mapped_column(String(128))
    expires_on: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    dry_run: Mapped[bool] = mapped_column(default=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    gap_count: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    gaps: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PurpleRun(Base):
    __tablename__ = "purple_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    dry_run: Mapped[bool] = mapped_column(default=True)
    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionObservation(Base):
    __tablename__ = "detection_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    purple_run_id: Mapped[str] = mapped_column(ForeignKey("purple_runs.id"), index=True)
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    detected: Mapped[bool] = mapped_column(default=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendation: Mapped[str] = mapped_column(Text, default="")


class TelemetryIngestionRun(Base):
    __tablename__ = "telemetry_ingestion_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32), default="wazuh")
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    fetched_count: Mapped[int] = mapped_column(Integer, default=0)
    stored_count: Mapped[int] = mapped_column(Integer, default=0)
    deduplicated_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    ingestion_run_id: Mapped[str] = mapped_column(ForeignKey("telemetry_ingestion_runs.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32), default="wazuh")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    rule_description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(String(1000), default="")
    safe_fields: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    raw_sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    operation: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="api")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def create_session_factory(database_url: str):
    if database_url.startswith("sqlite:///"):
        database_path = database_url.removeprefix("sqlite:///")
        if database_path not in {":memory:", ""}:
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
