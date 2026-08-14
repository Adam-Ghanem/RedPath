from __future__ import annotations

import hashlib
import json
from typing import Any, Callable
from uuid import uuid4

from app.core.redaction import redact_metadata, redact_text
from app.core.request_context import current_actor, current_tenant_id
from app.db.models import CaseGovernanceEvent, EvidenceCustodyEvent, EvidenceItem, utcnow
from app.schemas.contracts import EvidenceCustodyEventResponse, EvidenceCustodyVerifyRequest, GovernanceHistoryEvent

SessionFactory = Callable[[], object]


def immutable_evidence_payload(row: EvidenceItem) -> dict[str, str | None]:
    return {
        "evidence_id": row.id,
        "tenant_id": row.tenant_id,
        "campaign_id": row.campaign_id,
        "run_id": row.run_id,
        "evidence_type": row.evidence_type,
        "source": row.source,
        "title": row.title,
        "sha256": row.sha256,
        "technique_id": row.technique_id,
    }


def evidence_manifest_sha256(row: EvidenceItem) -> str:
    canonical = json.dumps(immutable_evidence_payload(row), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_evidence_custody(
    evidence_id: str,
    request: EvidenceCustodyVerifyRequest,
    session_factory: SessionFactory,
) -> EvidenceCustodyEventResponse:
    tenant_id = current_tenant_id()
    expected_manifest = request.manifest_sha256.lower()
    with session_factory() as session:
        row = session.query(EvidenceItem).filter_by(id=evidence_id, tenant_id=tenant_id).first()
        if row is None:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        if not row.campaign_id:
            raise ValueError("chain-of-custody verification requires case-linked evidence")
        actual_manifest = row.manifest_sha256 or evidence_manifest_sha256(row)
        if expected_manifest != actual_manifest:
            raise ValueError("custody manifest does not match immutable evidence manifest")
        now = utcnow()
        row.custody_status = request.decision
        row.custody_verified_by = current_actor()
        row.custody_verified_at = now
        row.custody_verification_sha256 = actual_manifest
        custody_event = EvidenceCustodyEvent(
            id=str(uuid4()),
            tenant_id=tenant_id,
            case_id=row.campaign_id,
            evidence_id=row.id,
            decision=request.decision,
            actor=current_actor(),
            manifest_sha256=actual_manifest,
            note=redact_text(request.note),
            created_at=now,
        )
        session.add(custody_event)
        record_governance_event(
            session,
            row.campaign_id,
            f"evidence.custody_{request.decision}",
            f"Evidence {row.title} custody marked {request.decision}.",
            {"evidence_id": row.id, "manifest_sha256": actual_manifest},
        )
        from app.services.case_compliance import record_decision_event  # noqa: PLC0415

        record_decision_event(
            session,
            row.campaign_id,
            "evidence",
            row.id,
            "evidence_custody_changed",
            None,
            request.decision,
            request.note,
            {"manifest_sha256": actual_manifest},
        )
        session.commit()
        session.refresh(custody_event)
    return EvidenceCustodyEventResponse(
        event_id=custody_event.id,
        tenant_id=custody_event.tenant_id,
        case_id=custody_event.case_id,
        evidence_id=custody_event.evidence_id,
        decision=custody_event.decision,
        actor=custody_event.actor,
        manifest_sha256=custody_event.manifest_sha256,
        note=custody_event.note,
        created_at=custody_event.created_at,
    )


def list_custody_history(case_id: str, session_factory: SessionFactory) -> list[EvidenceCustodyEventResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = (
            session.query(EvidenceCustodyEvent)
            .filter_by(case_id=case_id, tenant_id=tenant_id)
            .order_by(EvidenceCustodyEvent.created_at.asc(), EvidenceCustodyEvent.id.asc())
            .all()
        )
    return [
        EvidenceCustodyEventResponse(
            event_id=row.id,
            tenant_id=row.tenant_id,
            case_id=row.case_id,
            evidence_id=row.evidence_id,
            decision=row.decision,
            actor=row.actor,
            manifest_sha256=row.manifest_sha256,
            note=row.note,
            created_at=row.created_at,
        )
        for row in rows
    ]


def record_governance_event(
    session: object,
    case_id: str,
    event_type: str,
    summary: str,
    metadata: dict[str, Any] | None = None,
) -> CaseGovernanceEvent:
    event = CaseGovernanceEvent(
        id=str(uuid4()),
        tenant_id=current_tenant_id(),
        case_id=case_id,
        event_type=event_type,
        actor=current_actor(),
        summary=redact_text(summary),
        metadata_json=redact_metadata(metadata or {}),
        created_at=utcnow(),
    )
    session.add(event)
    return event


def list_governance_history(case_id: str, session_factory: SessionFactory) -> list[GovernanceHistoryEvent]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = (
            session.query(CaseGovernanceEvent)
            .filter_by(case_id=case_id, tenant_id=tenant_id)
            .order_by(CaseGovernanceEvent.created_at.asc(), CaseGovernanceEvent.id.asc())
            .all()
        )
    return [
        GovernanceHistoryEvent(
            event_id=row.id,
            tenant_id=row.tenant_id,
            case_id=row.case_id,
            event_type=row.event_type,
            actor=row.actor,
            summary=row.summary,
            metadata=dict(row.metadata_json or {}),
            created_at=row.created_at,
        )
        for row in rows
    ]
