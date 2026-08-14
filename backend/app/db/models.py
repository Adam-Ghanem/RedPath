from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
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
    mfa_verified_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceAccountToken(Base):
    __tablename__ = "service_account_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    service_account_id: Mapped[str] = mapped_column(ForeignKey("service_accounts.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_version: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    requester_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    requester_actor: Mapped[str] = mapped_column(String(128))
    requested_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    approver_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    approver_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_comment: Mapped[str | None] = mapped_column(String(500), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessGovernanceEvent(Base):
    __tablename__ = "access_governance_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
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
    __table_args__ = (
        Index("ix_discovery_jobs_tenant_status_lease", "tenant_id", "status", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
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
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recovery_count: Mapped[int] = mapped_column(Integer, default=0)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    retry_budget: Mapped[int] = mapped_column(Integer, default=2)
    retry_class: Mapped[str] = mapped_column(String(32), default="none")
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    checkpoint_stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checkpoint_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_compacted: Mapped[bool] = mapped_column(Boolean, default=False)
    result_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_tenant_ip", "tenant_id", "ip"),
        Index("ix_assets_tenant_last_seen", "tenant_id", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ports: Mapped[list[int]] = mapped_column(JSON, default=list)
    services: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    observation_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
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


class AttackPathAnalysis(Base):
    __tablename__ = "attack_path_analyses"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    actor_id: Mapped[str] = mapped_column(String(128))
    graph_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    custody_status: Mapped[str] = mapped_column(String(32), default="unverified", index=True)
    custody_verified_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    custody_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    custody_verification_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
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
    redaction_mode: Mapped[str] = mapped_column(String(32), default="pseudonymized")
    redacted_fields: Mapped[int] = mapped_column(Integer, default=0)
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    flows: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    dns_summary: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PcapLifecycle(Base):
    __tablename__ = "pcap_lifecycles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_items.id"), index=True)
    analysis_id: Mapped[str | None] = mapped_column(ForeignKey("pcap_analyses.id"), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(32), default="retained", index=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parse_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    storage_backend: Mapped[str] = mapped_column(String(32), default="metadata-only")
    storage_locator: Mapped[str] = mapped_column(String(16), default="none")
    raw_bytes_retained: Mapped[bool] = mapped_column(Boolean, default=False)
    stored_bytes: Mapped[int] = mapped_column(Integer, default=0)
    source_sha256: Mapped[str] = mapped_column(String(64), index=True)
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationItem(Base):
    __tablename__ = "remediation_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)
    finding_title: Mapped[str] = mapped_column(String(255))
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    recommendation: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(128), default="unassigned")
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    verification_status: Mapped[str] = mapped_column(String(32), default="unverified", index=True)
    verified_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    approval_status: Mapped[str] = mapped_column(String(32), default="approved", index=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    correlation_fields: Mapped[dict[str, str | int | bool]] = mapped_column(JSON, default=dict)
    raw_sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TelemetryIngestionState(Base):
    __tablename__ = "telemetry_ingestion_state"

    id: Mapped[str] = mapped_column(String(192), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32), default="wazuh")
    checkpoint_cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    cursor_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    schema_drift_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TelemetryDeadLetter(Base):
    __tablename__ = "telemetry_dead_letters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32), default="wazuh")
    error_code: Mapped[str] = mapped_column(String(64), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    retry_after_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceCustodyEvent(Base):
    __tablename__ = "evidence_custody_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_items.id"), index=True)
    decision: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CaseGovernanceEvent(Base):
    __tablename__ = "case_governance_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    summary: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), default="legacy", index=True)
    operation: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="api")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def _alembic_config(database_url: str) -> Config:
    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    config.attributes["database_url"] = database_url
    return config


def run_alembic_migrations(database_url: str, target: str = "head") -> None:
    """Upgrade the configured database through RedPath's sole Alembic revision chain."""
    command.upgrade(_alembic_config(database_url), target)


def run_alembic_downgrade(database_url: str, target: str = "base") -> None:
    """Downgrade only through Alembic for lifecycle checks and controlled rollback."""
    command.downgrade(_alembic_config(database_url), target)


def create_session_factory(database_url: str):
    if database_url.startswith("sqlite:///"):
        database_path = database_url.removeprefix("sqlite:///")
        if database_path not in {":memory:", ""}:
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    run_alembic_migrations(database_url)
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
