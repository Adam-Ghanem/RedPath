from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    inspect,
    text,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    role: Mapped[str] = mapped_column(String(64), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    session_version: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    mode: Mapped[str] = mapped_column(String(32), default="recon")
    dry_run: Mapped[bool] = mapped_column(default=True)
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assets: Mapped[list["Asset"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    profile: Mapped[str] = mapped_column(String(32), default="safe")
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    dry_run: Mapped[bool] = mapped_column(default=True)
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    label: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))
    criticality: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    rationale: Mapped[str] = mapped_column(Text, default="")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("assessment_runs.id"), index=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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


class PcapAnalysis(Base):
    __tablename__ = "pcap_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_items.id"), index=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    file_size: Mapped[int] = mapped_column(Integer)
    capture_format: Mapped[str] = mapped_column(String(16))
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    first_packet_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_packet_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    protocol_counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    endpoints: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    dns_queries: Mapped[list[str]] = mapped_column(JSON, default=list)
    observations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationItem(Base):
    __tablename__ = "remediation_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
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
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    dry_run: Mapped[bool] = mapped_column(default=True)
    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionObservation(Base):
    __tablename__ = "detection_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    purple_run_id: Mapped[str] = mapped_column(ForeignKey("purple_runs.id"), index=True)
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    detected: Mapped[bool] = mapped_column(default=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendation: Mapped[str] = mapped_column(Text, default="")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    operation: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="api")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_TENANT_TABLES = (
    "scan_runs",
    "assets",
    "findings",
    "graph_nodes",
    "graph_edges",
    "campaigns",
    "campaign_run_links",
    "evidence_items",
    "remediation_items",
    "risk_acceptances",
    "assessment_runs",
    "purple_runs",
    "detection_observations",
    "audit_events",
)


def run_migrations(engine) -> None:
    """Apply small, idempotent migrations without destructive data operations."""
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at VARCHAR(64) NOT NULL)"
            )
        )
        legacy_tenant = connection.execute(text("SELECT id FROM tenants WHERE id = 'legacy'")).first()
        if legacy_tenant is None:
            connection.execute(
                text(
                    "INSERT INTO tenants (id, slug, name, is_active, created_at) "
                    "VALUES ('legacy', 'legacy', 'Legacy imported records', 1, :created_at)"
                ),
                {"created_at": utcnow().isoformat()},
            )
        applied = connection.execute(text("SELECT version FROM schema_migrations WHERE version = 2")).first()
        if applied:
            return
        inspector = inspect(connection)
        for table_name in _TENANT_TABLES:
            if table_name not in inspector.get_table_names():
                continue
            columns = {column["name"] for column in inspector.get_columns(table_name)}
            if "tenant_id" not in columns:
                connection.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN tenant_id VARCHAR(128)'))
            connection.execute(text(f'UPDATE "{table_name}" SET tenant_id = :tenant_id WHERE tenant_id IS NULL'), {"tenant_id": "legacy"})
        connection.execute(
            text("INSERT INTO schema_migrations (version, applied_at) VALUES (2, :applied_at)"),
            {"applied_at": utcnow().isoformat()},
        )


def create_session_factory(database_url: str):
    if database_url.startswith("sqlite:///"):
        database_path = database_url.removeprefix("sqlite:///")
        if database_path not in {":memory:", ""}:
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    run_migrations(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
