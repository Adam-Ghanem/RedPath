from __future__ import annotations

from datetime import date
from typing import Callable

from app.core.request_context import current_tenant_id
from app.db.models import Campaign, EvidenceItem, RemediationItem, RiskAcceptance, utcnow
from app.schemas.contracts import CampaignResponse, CaseStatusUpdate
from app.services.case_governance import record_governance_event
from app.services.expert_ops import _campaign_response
from app.services.governance import GovernanceViolation

SessionFactory = Callable[[], object]

_CASE_TRANSITIONS = {
    "active": {"active", "on_hold", "closed"},
    "on_hold": {"active", "on_hold", "closed"},
    "closed": {"closed"},
}


def list_cases(session_factory: SessionFactory) -> list[CampaignResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = session.query(Campaign).filter_by(tenant_id=tenant_id).order_by(Campaign.updated_at.desc()).all()
    return [_campaign_response(row) for row in rows]


def _assert_close_ready(session: object, case_id: str, tenant_id: str) -> None:
    evidence = session.query(EvidenceItem).filter_by(campaign_id=case_id, tenant_id=tenant_id).all()
    if not evidence:
        raise GovernanceViolation("case cannot close without registered evidence")
    if any(item.review_status != "accepted" for item in evidence):
        raise GovernanceViolation("case cannot close until all evidence is accepted")

    remediations = session.query(RemediationItem).filter_by(campaign_id=case_id, tenant_id=tenant_id).all()
    active_acceptances = {
        item.remediation_id
        for item in session.query(RiskAcceptance)
        .filter_by(campaign_id=case_id, tenant_id=tenant_id, status="active")
        .filter(RiskAcceptance.expires_on >= date.today().isoformat())
        .all()
        if item.remediation_id
    }
    unresolved = [
        item
        for item in remediations
        if item.status not in {"resolved", "closed"} and item.id not in active_acceptances
    ]
    if unresolved:
        raise GovernanceViolation("case cannot close with unresolved remediation lacking active risk acceptance")


def update_case_status(
    case_id: str,
    request: CaseStatusUpdate,
    session_factory: SessionFactory,
) -> CampaignResponse:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        row = session.query(Campaign).filter_by(id=case_id, tenant_id=tenant_id).first()
        if row is None:
            raise KeyError(f"Unknown case: {case_id}")
        if request.status not in _CASE_TRANSITIONS.get(row.status, set()):
            raise GovernanceViolation(f"case transition {row.status!r} -> {request.status!r} is not allowed")
        if request.status == "closed":
            _assert_close_ready(session, case_id, tenant_id)
        previous_status = row.status
        row.status = request.status
        row.updated_at = utcnow()
        record_governance_event(
            session,
            case_id,
            "case.status_changed",
            request.note or f"Case status changed from {previous_status} to {request.status}.",
            {"from": previous_status, "to": request.status},
        )
        session.commit()
        session.refresh(row)
    return _campaign_response(row)
