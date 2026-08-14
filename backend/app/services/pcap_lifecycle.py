from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from app.core.ownership import tenant_query
from app.db.models import EvidenceItem, PcapAnalysis, PcapLifecycle, utcnow
from app.schemas.pcap import (
    PcapDeletionCheckResponse,
    PcapDnsSummary,
    PcapDrilldownResponse,
    PcapFlowSummary,
    PcapLifecycleResponse,
    PcapManifestVerification,
    PcapObservation,
    PcapRedactionVerification,
    PcapStorageMetadata,
)
from app.services.case_governance import evidence_manifest_sha256

SessionFactory = Callable[[], Any]


class PcapLifecycleViolation(ValueError):
    """A safe lifecycle or privacy verification boundary rejected the request."""


_FAILURE_MESSAGES = {
    "unsupported_format": "Capture format is not supported.",
    "truncated_capture": "Capture framing could not be completed.",
    "invalid_capture_length": "Capture packet framing is invalid.",
    "timestamp_out_of_range": "Capture timestamps are outside the supported range.",
    "parse_failed": "Offline capture validation failed.",
}


def safe_parse_failure(exc: Exception) -> tuple[str, str]:
    message = str(exc).lower()
    if "unsupported capture" in message or "byte order" in message:
        code = "unsupported_format"
    elif "timestamp" in message:
        code = "timestamp_out_of_range"
    elif "length" in message:
        code = "invalid_capture_length"
    elif "truncated" in message:
        code = "truncated_capture"
    else:
        code = "parse_failed"
    return code, _FAILURE_MESSAGES[code]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _retention_until(days: int, now: datetime) -> datetime:
    if days < 1 or days > 3_650:
        raise ValueError("PCAP retention days must be between 1 and 3650")
    return now + timedelta(days=days)


def _storage_metadata(source_sha256: str) -> PcapStorageMetadata:
    return PcapStorageMetadata(source_sha256=source_sha256)


def lifecycle_response(row: PcapLifecycle) -> PcapLifecycleResponse:
    return PcapLifecycleResponse(
        lifecycle_id=row.id,
        tenant_id=row.tenant_id,
        evidence_id=row.evidence_id,
        analysis_id=row.analysis_id,
        state=row.state,
        failure_code=row.failure_code,
        parse_error=row.parse_error,
        storage=_storage_metadata(row.source_sha256),
        retention_until=_as_utc(row.retention_until),
        legal_hold=row.legal_hold,
        manifest_sha256=row.manifest_sha256,
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


def create_retained_lifecycle(
    session: Any,
    evidence: EvidenceItem,
    analysis_id: str,
    retention_days: int,
) -> PcapLifecycle:
    now = utcnow()
    manifest = evidence_manifest_sha256(evidence)
    evidence.manifest_sha256 = manifest
    lifecycle = PcapLifecycle(
        id=str(uuid4()),
        tenant_id=evidence.tenant_id,
        evidence_id=evidence.id,
        analysis_id=analysis_id,
        state="retained",
        storage_backend="metadata-only",
        storage_locator="none",
        raw_bytes_retained=False,
        stored_bytes=0,
        source_sha256=evidence.sha256,
        retention_until=_retention_until(retention_days, now),
        legal_hold=False,
        manifest_sha256=manifest,
        created_at=now,
        updated_at=now,
    )
    session.add(lifecycle)
    return lifecycle


def quarantine_pcap(
    data: bytes,
    file_name: str,
    tenant_id: str,
    session_factory: SessionFactory,
    *,
    failure_code: str,
    parse_error: str,
    retention_days: int,
) -> PcapLifecycleResponse:
    if failure_code not in _FAILURE_MESSAGES:
        failure_code = "parse_failed"
    safe_error = _FAILURE_MESSAGES[failure_code]
    now = utcnow()
    source_sha256 = hashlib.sha256(data).hexdigest()
    with session_factory() as session:
        evidence = EvidenceItem(
            id=str(uuid4()),
            tenant_id=tenant_id,
            evidence_type="pcap",
            source="offline-upload-quarantine",
            title=file_name,
            sha256=source_sha256,
            review_status="unreviewed",
            notes="Capture was quarantined after offline validation failed; raw capture bytes were not retained.",
            created_at=now,
        )
        session.add(evidence)
        session.flush()
        manifest = evidence_manifest_sha256(evidence)
        evidence.manifest_sha256 = manifest
        lifecycle = PcapLifecycle(
            id=str(uuid4()),
            tenant_id=tenant_id,
            evidence_id=evidence.id,
            analysis_id=None,
            state="quarantined",
            failure_code=failure_code,
            parse_error=safe_error if parse_error else safe_error,
            storage_backend="metadata-only",
            storage_locator="none",
            raw_bytes_retained=False,
            stored_bytes=0,
            source_sha256=source_sha256,
            retention_until=_retention_until(retention_days, now),
            legal_hold=False,
            manifest_sha256=manifest,
            created_at=now,
            updated_at=now,
        )
        session.add(lifecycle)
        session.commit()
        session.refresh(lifecycle)
    return lifecycle_response(lifecycle)


def _get_lifecycle_row(
    evidence_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
) -> PcapLifecycle:
    with session_factory() as session:
        row = (
            tenant_query(session.query(PcapLifecycle), PcapLifecycle, tenant_id)
            .filter(PcapLifecycle.evidence_id == evidence_id)
            .one_or_none()
        )
    if row is None:
        raise KeyError(f"Unknown PCAP lifecycle: {evidence_id}")
    return row


def get_pcap_lifecycle(
    evidence_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
) -> PcapLifecycleResponse:
    return lifecycle_response(_get_lifecycle_row(evidence_id, tenant_id, session_factory))


def list_pcap_lifecycles(
    tenant_id: str,
    session_factory: SessionFactory,
    *,
    state: str | None = None,
    limit: int = 20,
) -> list[PcapLifecycleResponse]:
    if state is not None and state not in {"retained", "quarantined", "deletion_pending", "deleted"}:
        raise ValueError("invalid PCAP lifecycle state")
    with session_factory() as session:
        query = tenant_query(session.query(PcapLifecycle), PcapLifecycle, tenant_id)
        if state is not None:
            query = query.filter(PcapLifecycle.state == state)
        rows = query.order_by(PcapLifecycle.created_at.desc()).limit(max(1, min(limit, 100))).all()
    return [lifecycle_response(row) for row in rows]


def _manifest_verification(evidence: EvidenceItem, lifecycle: PcapLifecycle) -> PcapManifestVerification:
    computed = evidence_manifest_sha256(evidence)
    stored = evidence.manifest_sha256 or lifecycle.manifest_sha256
    valid = computed == lifecycle.manifest_sha256 and stored == lifecycle.manifest_sha256
    return PcapManifestVerification(
        evidence_id=evidence.id,
        valid=valid,
        computed_manifest_sha256=computed,
        stored_manifest_sha256=stored,
        checked_at=datetime.now(timezone.utc),
        failure_code=None if valid else "manifest_mismatch",
    )


def _flow_endpoint_is_redacted(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    endpoint = value.rsplit(":", 1)[0] if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit() else value
    return endpoint.startswith("ip_")


def _raw_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.rsplit(":", 1)[0] if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit() else value
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def verify_redaction(analysis: PcapAnalysis) -> PcapRedactionVerification:
    violations: set[str] = set()
    checked = 0
    if analysis.redaction_mode != "pseudonymized":
        violations.add("redaction_mode_invalid")
    for endpoint in analysis.endpoints or []:
        checked += 1
        if not _flow_endpoint_is_redacted(endpoint.get("ip")) or _raw_ip(endpoint.get("ip")):
            violations.add("raw_endpoint_identifier")
    for flow in analysis.flows or []:
        checked += 2
        if not _flow_endpoint_is_redacted(flow.get("source")) or not _flow_endpoint_is_redacted(
            flow.get("destination")
        ):
            violations.add("raw_flow_identifier")
        if _raw_ip(flow.get("source")) or _raw_ip(flow.get("destination")):
            violations.add("raw_flow_ip")
    for dns in analysis.dns_summary or []:
        checked += 1
        if not str(dns.get("query", "")).startswith("dns_"):
            violations.add("raw_dns_identifier")
    for query in analysis.dns_queries or []:
        checked += 1
        if not str(query).startswith("dns_"):
            violations.add("raw_dns_query")
    for observation in analysis.observations or []:
        checked += 2
        for field in ("source_ip", "destination_ip"):
            value = observation.get(field)
            if value is not None and (not str(value).startswith("ip_") or _raw_ip(value)):
                violations.add("raw_observation_identifier")
        attributes = observation.get("attributes") or {}
        for key, value in attributes.items():
            checked += 1
            if key == "query":
                if not str(value).startswith("dns_"):
                    violations.add("raw_observation_dns")
            elif key != "captured_bytes":
                violations.add("unexpected_payload_attribute")
    return PcapRedactionVerification(
        valid=not violations,
        checked_fields=checked,
        violation_codes=sorted(violations),
    )


def _get_analysis_bundle(
    analysis_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
) -> tuple[PcapAnalysis, EvidenceItem, PcapLifecycle]:
    with session_factory() as session:
        row = (
            session.query(PcapAnalysis, EvidenceItem, PcapLifecycle)
            .join(EvidenceItem, EvidenceItem.id == PcapAnalysis.evidence_id)
            .join(PcapLifecycle, PcapLifecycle.analysis_id == PcapAnalysis.id)
            .filter(
                PcapAnalysis.id == analysis_id,
                PcapAnalysis.tenant_id == tenant_id,
                EvidenceItem.tenant_id == tenant_id,
                PcapLifecycle.tenant_id == tenant_id,
            )
            .one_or_none()
        )
    if row is None:
        raise KeyError(f"Unknown PCAP analysis: {analysis_id}")
    return row


def get_pcap_manifest(
    evidence_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
) -> PcapManifestVerification:
    with session_factory() as session:
        row = (
            session.query(EvidenceItem, PcapLifecycle)
            .join(PcapLifecycle, PcapLifecycle.evidence_id == EvidenceItem.id)
            .filter(
                EvidenceItem.id == evidence_id,
                EvidenceItem.tenant_id == tenant_id,
                PcapLifecycle.tenant_id == tenant_id,
            )
            .one_or_none()
        )
    if row is None:
        raise KeyError(f"Unknown PCAP evidence: {evidence_id}")
    evidence, lifecycle = row
    return _manifest_verification(evidence, lifecycle)


def get_pcap_lifecycle_views(
    analysis_id: str,
    evidence_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
) -> tuple[PcapLifecycleResponse | None, PcapManifestVerification | None, PcapRedactionVerification | None]:
    try:
        analysis, evidence, lifecycle = _get_analysis_bundle(analysis_id, tenant_id, session_factory)
    except KeyError:
        return None, None, None
    if evidence.id != evidence_id:
        return None, None, None
    return lifecycle_response(lifecycle), _manifest_verification(evidence, lifecycle), verify_redaction(analysis)


def get_pcap_drilldown(
    analysis_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
    *,
    max_flows: int = 25,
    max_dns: int = 25,
    max_observations: int = 100,
) -> PcapDrilldownResponse:
    if min(max_flows, max_dns, max_observations) < 1:
        raise ValueError("PCAP drill-down limits must be positive")
    analysis, evidence, lifecycle = _get_analysis_bundle(analysis_id, tenant_id, session_factory)
    manifest = _manifest_verification(evidence, lifecycle)
    redaction = verify_redaction(analysis)
    if not manifest.valid:
        raise PcapLifecycleViolation("PCAP manifest verification failed")
    if not redaction.valid:
        raise PcapLifecycleViolation("PCAP redaction verification failed")
    return PcapDrilldownResponse(
        analysis_id=analysis.id,
        evidence_id=analysis.evidence_id,
        tenant_id=analysis.tenant_id,
        lifecycle=lifecycle_response(lifecycle),
        manifest=manifest,
        redaction=redaction,
        flows=[PcapFlowSummary.model_validate(item) for item in (analysis.flows or [])[:max_flows]],
        dns_summary=[PcapDnsSummary.model_validate(item) for item in (analysis.dns_summary or [])[:max_dns]],
        observations=[
            PcapObservation.model_validate(item)
            for item in (analysis.observations or [])[:max_observations]
        ],
        warnings=(analysis.warnings or [])[:100],
    )


def check_pcap_deletion(
    evidence_id: str,
    tenant_id: str,
    session_factory: SessionFactory,
    *,
    now: datetime | None = None,
) -> PcapDeletionCheckResponse:
    row = _get_lifecycle_row(evidence_id, tenant_id, session_factory)
    current = now or datetime.now(timezone.utc)
    blockers: list[str] = []
    if row.state == "deleted":
        blockers.append("already_deleted")
    if row.legal_hold:
        blockers.append("legal_hold")
    retention_until = _as_utc(row.retention_until)
    if _as_utc(current) < retention_until:
        blockers.append("retention_active")
    if row.state == "deletion_pending":
        blockers.append("deletion_already_pending")
    if row.state not in {"retained", "quarantined", "deletion_pending", "deleted"}:
        blockers.append("invalid_lifecycle_state")
    return PcapDeletionCheckResponse(
        evidence_id=evidence_id,
        allowed=not blockers,
        blockers=sorted(set(blockers)),
        retention_until=retention_until,
        legal_hold=row.legal_hold,
        state=row.state,
    )
