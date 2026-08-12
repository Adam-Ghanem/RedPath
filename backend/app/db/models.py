from __future__ import annotations

from datetime import datetime, timezone
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


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    operation: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="api")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def create_session_factory(database_url: str):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
