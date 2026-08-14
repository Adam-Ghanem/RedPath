from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.contracts import EvidenceResponse


class PcapEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=1, max_length=64)
    packet_count: int = Field(ge=1)
    byte_count: int = Field(ge=0)


class PcapFlowSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flow_id: str
    protocol: Literal["tcp", "udp", "icmp", "other"]
    source: str = Field(min_length=1, max_length=128)
    destination: str = Field(min_length=1, max_length=128)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    packet_count: int = Field(ge=1)
    byte_count: int = Field(ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class PcapDnsSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=255)
    count: int = Field(ge=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class PcapObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp_utc: datetime
    observation_type: Literal["flow", "dns_query", "http_request"]
    protocol: Literal["tcp", "udp", "icmp", "other"]
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    attributes: dict[str, Any] = Field(default_factory=dict)


class PcapAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    analysis_id: str
    evidence_id: str
    tenant_id: str = Field(min_length=1, max_length=128)
    campaign_id: str | None = None
    file_name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_size: int = Field(ge=24)
    capture_format: Literal["pcap", "pcapng"]
    packet_count: int = Field(ge=0)
    first_packet_at: datetime | None = None
    last_packet_at: datetime | None = None
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    endpoints: list[PcapEndpoint] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)
    observations: list[PcapObservation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    redaction_mode: Literal["pseudonymized"] = "pseudonymized"
    redacted_fields: int = Field(default=0, ge=0)
    flow_count: int = Field(default=0, ge=0)
    flows: list[PcapFlowSummary] = Field(default_factory=list)
    dns_summary: list[PcapDnsSummary] = Field(default_factory=list)
    created_at: datetime


class PcapAnalysisSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    tenant_id: str
    evidence_id: str
    file_name: str
    sha256: str
    capture_format: Literal["pcap", "pcapng"]
    packet_count: int = Field(ge=0)
    campaign_id: str | None = None
    evidence_title: str | None = None
    review_status: str = "unreviewed"
    redaction_mode: Literal["pseudonymized"] = "pseudonymized"
    redacted_fields: int = Field(default=0, ge=0)
    flow_count: int = Field(default=0, ge=0)
    dns_count: int = Field(default=0, ge=0)
    created_at: datetime


class PcapStorageMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    storage_backend: Literal["metadata-only"] = "metadata-only"
    storage_locator: Literal["none"] = "none"
    raw_bytes_retained: Literal[False] = False
    stored_bytes: int = Field(default=0, ge=0, le=0)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PcapManifestVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    valid: bool
    computed_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stored_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    checked_at: datetime
    failure_code: str | None = None


class PcapRedactionVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    checked_fields: int = Field(ge=0)
    violation_codes: list[str] = Field(default_factory=list, max_length=16)
    mode: Literal["pseudonymized"] = "pseudonymized"


class PcapLifecycleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifecycle_id: str
    tenant_id: str
    evidence_id: str
    analysis_id: str | None = None
    state: Literal["retained", "quarantined", "deletion_pending", "deleted"]
    failure_code: str | None = None
    parse_error: str | None = None
    storage: PcapStorageMetadata
    retention_until: datetime
    legal_hold: bool = False
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    updated_at: datetime


class PcapDeletionCheckResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    allowed: bool
    dry_run: Literal[True] = True
    blockers: list[str] = Field(default_factory=list, max_length=8)
    retention_until: datetime
    legal_hold: bool = False
    state: Literal["retained", "quarantined", "deletion_pending", "deleted"]


class PcapDrilldownResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    evidence_id: str
    tenant_id: str
    lifecycle: PcapLifecycleResponse
    manifest: PcapManifestVerification
    redaction: PcapRedactionVerification
    flows: list[PcapFlowSummary] = Field(default_factory=list, max_length=25)
    dns_summary: list[PcapDnsSummary] = Field(default_factory=list, max_length=25)
    observations: list[PcapObservation] = Field(default_factory=list, max_length=100)
    warnings: list[str] = Field(default_factory=list, max_length=100)


class PcapEvidenceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence: EvidenceResponse
    analysis: PcapAnalysisResponse
    lifecycle: PcapLifecycleResponse | None = None
    manifest: PcapManifestVerification | None = None
    redaction: PcapRedactionVerification | None = None
