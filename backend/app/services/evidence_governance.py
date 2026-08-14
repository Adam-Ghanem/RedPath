from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from app.core.ownership import tenant_query
from app.core.redaction import redact_text
from app.core.request_context import current_actor, current_tenant_id
from app.db.models import (
    EvidenceDeletionRequest,
    EvidenceItem,
    EvidenceLegalHold,
    EvidenceRetentionDecision,
    PcapLifecycle,
    utcnow,
)
from app.schemas.contracts import (
    EvidenceDeletionDecisionRequest,
    EvidenceDeletionRequestCreate,
    EvidenceDeletionRequestResponse,
    EvidenceIntegrityResponse,
    EvidenceLegalHoldRequest,
    EvidenceLegalHoldResponse,
    EvidencePrivacySummary,
    EvidenceRetentionDecisionRequest,
    EvidenceRetentionDecisionResponse,
    EvidenceStorageMetadata,
)
from app.services.case_governance import evidence_manifest_sha256

SessionFactory = Callable[[], Any]


class EvidenceGovernanceViolation(ValueError):
    """A requested evidence governance transition is not safe or authorized."""


class EvidenceStorageProvider(Protocol):
    def metadata(self, evidence: EvidenceItem, lifecycle: PcapLifecycle | None) -> EvidenceStorageMetadata:
        """Return bounded storage metadata without exposing content or a locator."""

    def verify(self, evidence: EvidenceItem, lifecycle: PcapLifecycle | None) -> tuple[bool, str | None]:
        """Verify that storage metadata matches the evidence hash without reading payloads."""


class MetadataOnlyStorageProvider:
    """Storage seam for evidence paths that intentionally retain metadata only."""

    def metadata(self, evidence: EvidenceItem, lifecycle: PcapLifecycle | None) -> EvidenceStorageMetadata:
        return EvidenceStorageMetadata(source_sha256=evidence.sha256)

    def verify(self, evidence: EvidenceItem, lifecycle: PcapLifecycle | None) -> tuple[bool, str | None]:
        if lifecycle is None:
            return True, None
        if lifecycle.storage_backend != "metadata-only":
            return False, "storage_backend_invalid"
        if lifecycle.storage_locator != "none":
            return False, "storage_locator_present"
        if lifecycle.raw_bytes_retained or lifecycle.stored_bytes != 0:
            return False, "raw_storage_present"
        if lifecycle.source_sha256 != evidence.sha256:
            return False, "source_hash_mismatch"
        return True, None


_STORAGE_PROVIDER: EvidenceStorageProvider = MetadataOnlyStorageProvider()


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _evidence(session: Any, evidence_id: str, tenant_id: str) -> EvidenceItem:
    row = (
        tenant_query(session.query(EvidenceItem), EvidenceItem, tenant_id)
        .filter(EvidenceItem.id == evidence_id)
        .one_or_none()
    )
    if row is None:
        raise KeyError(f"Unknown evidence: {evidence_id}")
    return row


def _lifecycle(session: Any, evidence_id: str, tenant_id: str) -> PcapLifecycle | None:
    return (
        tenant_query(session.query(PcapLifecycle), PcapLifecycle, tenant_id)
        .filter(PcapLifecycle.evidence_id == evidence_id)
        .one_or_none()
    )


def _hold_response(row: EvidenceLegalHold | None, evidence_id: str, tenant_id: str) -> EvidenceLegalHoldResponse:
    if row is None:
        now = utcnow()
        return EvidenceLegalHoldResponse(evidence_id=evidence_id, tenant_id=tenant_id, active=False, updated_at=now)
    return EvidenceLegalHoldResponse(
        evidence_id=row.evidence_id,
        tenant_id=row.tenant_id,
        active=row.active,
        reason=row.reason,
        placed_by=row.placed_by,
        placed_at=_as_utc(row.placed_at),
        released_by=row.released_by,
        released_at=_as_utc(row.released_at),
        updated_at=_as_utc(row.updated_at) or utcnow(),
    )


def set_legal_hold(
    evidence_id: str,
    request: EvidenceLegalHoldRequest,
    session_factory: SessionFactory,
) -> EvidenceLegalHoldResponse:
    tenant_id = current_tenant_id()
    actor = current_actor()
    now = utcnow()
    with session_factory() as session:
        _evidence(session, evidence_id, tenant_id)
        row = (
            tenant_query(session.query(EvidenceLegalHold), EvidenceLegalHold, tenant_id)
            .filter(EvidenceLegalHold.evidence_id == evidence_id)
            .one_or_none()
        )
        if row is None:
            row = EvidenceLegalHold(
                id=str(uuid4()), tenant_id=tenant_id, evidence_id=evidence_id, updated_at=now
            )
            session.add(row)
        row.reason = redact_text(request.reason)
        row.updated_at = now
        if request.action == "place":
            row.active = True
            row.placed_by = actor
            row.placed_at = now
        else:
            row.active = False
            row.released_by = actor
            row.released_at = now
        lifecycle = _lifecycle(session, evidence_id, tenant_id)
        if lifecycle is not None:
            lifecycle.legal_hold = row.active
            lifecycle.updated_at = now
        session.commit()
        session.refresh(row)
    return _hold_response(row, evidence_id, tenant_id)


def get_legal_hold(evidence_id: str, session_factory: SessionFactory) -> EvidenceLegalHoldResponse:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        _evidence(session, evidence_id, tenant_id)
        row = (
            tenant_query(session.query(EvidenceLegalHold), EvidenceLegalHold, tenant_id)
            .filter(EvidenceLegalHold.evidence_id == evidence_id)
            .one_or_none()
        )
    return _hold_response(row, evidence_id, tenant_id)


def _retention_response(row: EvidenceRetentionDecision) -> EvidenceRetentionDecisionResponse:
    return EvidenceRetentionDecisionResponse(
        decision_id=row.id,
        evidence_id=row.evidence_id,
        tenant_id=row.tenant_id,
        decision=row.decision,
        reason=row.reason,
        actor=row.actor,
        created_at=_as_utc(row.created_at) or utcnow(),
    )


def create_retention_decision(
    evidence_id: str,
    request: EvidenceRetentionDecisionRequest,
    session_factory: SessionFactory,
) -> EvidenceRetentionDecisionResponse:
    tenant_id = current_tenant_id()
    row = EvidenceRetentionDecision(
        id=str(uuid4()),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        decision=request.decision,
        reason=redact_text(request.reason),
        actor=current_actor(),
        created_at=utcnow(),
    )
    with session_factory() as session:
        _evidence(session, evidence_id, tenant_id)
        session.add(row)
        session.commit()
        session.refresh(row)
    return _retention_response(row)


def list_retention_decisions(
    evidence_id: str,
    session_factory: SessionFactory,
    *,
    limit: int = 50,
) -> list[EvidenceRetentionDecisionResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        _evidence(session, evidence_id, tenant_id)
        rows = (
            tenant_query(session.query(EvidenceRetentionDecision), EvidenceRetentionDecision, tenant_id)
            .filter(EvidenceRetentionDecision.evidence_id == evidence_id)
            .order_by(EvidenceRetentionDecision.created_at.asc(), EvidenceRetentionDecision.id.asc())
            .limit(max(1, min(limit, 100)))
            .all()
        )
    return [_retention_response(row) for row in rows]


def _deletion_response(row: EvidenceDeletionRequest) -> EvidenceDeletionRequestResponse:
    return EvidenceDeletionRequestResponse(
        request_id=row.id,
        evidence_id=row.evidence_id,
        tenant_id=row.tenant_id,
        state=row.state,
        reason=row.reason,
        requested_by=row.requested_by,
        requested_at=_as_utc(row.requested_at) or utcnow(),
        decided_by=row.decided_by,
        decided_at=_as_utc(row.decided_at),
        decision_note=row.decision_note,
    )


def _latest_retention(session: Any, evidence_id: str, tenant_id: str) -> EvidenceRetentionDecision | None:
    return (
        tenant_query(session.query(EvidenceRetentionDecision), EvidenceRetentionDecision, tenant_id)
        .filter(EvidenceRetentionDecision.evidence_id == evidence_id)
        .order_by(EvidenceRetentionDecision.created_at.desc(), EvidenceRetentionDecision.id.desc())
        .first()
    )


def request_deletion(
    evidence_id: str,
    request: EvidenceDeletionRequestCreate,
    session_factory: SessionFactory,
) -> EvidenceDeletionRequestResponse:
    tenant_id = current_tenant_id()
    actor = current_actor()
    now = utcnow()
    with session_factory() as session:
        _evidence(session, evidence_id, tenant_id)
        hold = (
            tenant_query(session.query(EvidenceLegalHold), EvidenceLegalHold, tenant_id)
            .filter(EvidenceLegalHold.evidence_id == evidence_id, EvidenceLegalHold.active.is_(True))
            .one_or_none()
        )
        if hold is not None:
            raise EvidenceGovernanceViolation("legal hold blocks deletion request")
        latest = _latest_retention(session, evidence_id, tenant_id)
        if latest is None or latest.decision != "eligible_for_deletion":
            raise EvidenceGovernanceViolation("eligible_for_deletion retention decision is required")
        pending = (
            tenant_query(session.query(EvidenceDeletionRequest), EvidenceDeletionRequest, tenant_id)
            .filter(
                EvidenceDeletionRequest.evidence_id == evidence_id,
                EvidenceDeletionRequest.state == "requested",
            )
            .first()
        )
        if pending is not None:
            raise EvidenceGovernanceViolation("a deletion request is already pending")
        row = EvidenceDeletionRequest(
            id=str(uuid4()),
            tenant_id=tenant_id,
            evidence_id=evidence_id,
            state="requested",
            reason=redact_text(request.reason),
            requested_by=actor,
            requested_at=now,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
    return _deletion_response(row)


def decide_deletion(
    evidence_id: str,
    request_id: str,
    request: EvidenceDeletionDecisionRequest,
    session_factory: SessionFactory,
) -> EvidenceDeletionRequestResponse:
    tenant_id = current_tenant_id()
    actor = current_actor()
    now = utcnow()
    with session_factory() as session:
        _evidence(session, evidence_id, tenant_id)
        row = (
            tenant_query(session.query(EvidenceDeletionRequest), EvidenceDeletionRequest, tenant_id)
            .filter(EvidenceDeletionRequest.id == request_id, EvidenceDeletionRequest.evidence_id == evidence_id)
            .one_or_none()
        )
        if row is None:
            raise KeyError(f"Unknown deletion request: {request_id}")
        if row.state != "requested":
            raise EvidenceGovernanceViolation("deletion request is already decided")
        if request.decision == "approve":
            if actor == row.requested_by:
                raise EvidenceGovernanceViolation("deletion approval requires a different actor")
            hold = (
                tenant_query(session.query(EvidenceLegalHold), EvidenceLegalHold, tenant_id)
                .filter(EvidenceLegalHold.evidence_id == evidence_id, EvidenceLegalHold.active.is_(True))
                .one_or_none()
            )
            latest = _latest_retention(session, evidence_id, tenant_id)
            if hold is not None or latest is None or latest.decision != "eligible_for_deletion":
                raise EvidenceGovernanceViolation("deletion approval boundary is not satisfied")
        row.state = "approved" if request.decision == "approve" else "rejected"
        row.decided_by = actor
        row.decided_at = now
        row.decision_note = redact_text(request.note)
        session.commit()
        session.refresh(row)
    return _deletion_response(row)


def privacy_summary(evidence_id: str, session_factory: SessionFactory) -> EvidencePrivacySummary:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        evidence = _evidence(session, evidence_id, tenant_id)
        lifecycle = _lifecycle(session, evidence_id, tenant_id)
        hold = (
            tenant_query(session.query(EvidenceLegalHold), EvidenceLegalHold, tenant_id)
            .filter(EvidenceLegalHold.evidence_id == evidence_id)
            .one_or_none()
        )
        retention = _latest_retention(session, evidence_id, tenant_id)
        deletion = (
            tenant_query(session.query(EvidenceDeletionRequest), EvidenceDeletionRequest, tenant_id)
            .filter(EvidenceDeletionRequest.evidence_id == evidence_id)
            .order_by(EvidenceDeletionRequest.requested_at.desc(), EvidenceDeletionRequest.id.desc())
            .first()
        )
        expected_manifest = evidence_manifest_sha256(evidence)
        stored_manifest = evidence.manifest_sha256
        manifest_verified = expected_manifest == stored_manifest
        if lifecycle is not None:
            manifest_verified = manifest_verified and lifecycle.manifest_sha256 == expected_manifest
        storage_valid, _ = _STORAGE_PROVIDER.verify(evidence, lifecycle)
        manifest_verified = manifest_verified and storage_valid
        storage = _STORAGE_PROVIDER.metadata(evidence, lifecycle)
    summary = "Metadata-only evidence; no raw packet or payload content is available through this summary."
    return EvidencePrivacySummary(
        evidence_id=evidence.id,
        tenant_id=evidence.tenant_id,
        evidence_type=evidence.evidence_type,
        review_status=evidence.review_status,
        custody_status=evidence.custody_status,
        legal_hold=bool(hold and hold.active),
        retention_decision=retention.decision if retention else None,
        deletion_request_state=deletion.state if deletion else None,
        manifest_verified=manifest_verified,
        storage=storage,
        summary=summary,
        created_at=_as_utc(evidence.created_at) or utcnow(),
    )


def reverify_integrity(evidence_id: str, session_factory: SessionFactory) -> EvidenceIntegrityResponse:
    tenant_id = current_tenant_id()
    checked_at = utcnow()
    with session_factory() as session:
        evidence = _evidence(session, evidence_id, tenant_id)
        lifecycle = _lifecycle(session, evidence_id, tenant_id)
        expected = evidence_manifest_sha256(evidence)
        stored = evidence.manifest_sha256
        source_sha256 = evidence.sha256
        manifest_valid = expected == stored
        lifecycle_manifest_valid = lifecycle is None or lifecycle.manifest_sha256 == expected
        storage_valid, storage_failure = _STORAGE_PROVIDER.verify(evidence, lifecycle)
        valid = manifest_valid and lifecycle_manifest_valid and storage_valid
        evidence.custody_status = "verified" if valid else "rejected"
        evidence.custody_verified_by = current_actor()
        evidence.custody_verified_at = checked_at
        evidence.custody_verification_sha256 = expected
        session.commit()
    return EvidenceIntegrityResponse(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        valid=valid,
        checked_at=checked_at,
        expected_manifest_sha256=expected,
        stored_manifest_sha256=stored,
        storage_backend="metadata-only",
        raw_bytes_retained=False,
        stored_bytes=0,
        source_sha256=source_sha256,
        failure_code=(
            None
            if valid
            else (
                storage_failure
                or ("lifecycle_manifest_mismatch" if not lifecycle_manifest_valid else "manifest_mismatch")
            )
        ),
    )
