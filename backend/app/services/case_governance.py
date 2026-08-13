from __future__ import annotations

import hashlib
import json
from typing import Any, Callable
from uuid import uuid4

from app.core.redaction import redact_metadata, redact_text
from app.core.request_context import current_actor, current_tenant_id
from app.db.models import CaseGovernanceEvent, EvidenceItem, utcnow
from app.schemas.contracts import GovernanceHistoryEvent

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
