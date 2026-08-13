from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from app.core.ownership import tenant_query
from app.core.redaction import redact_text
from app.core.request_context import current_actor, current_tenant_id
from app.db.models import AssessmentRun, Campaign, EvidenceItem, RemediationItem, RiskAcceptance, utcnow
from app.schemas.contracts import (
    CoverageScorecard,
    EvidenceResponse,
    EvidenceReviewUpdate,
    ExecutiveKpis,
    RemediationLifecycleUpdate,
    RemediationResponse,
    RiskAcceptanceCreate,
    RiskAcceptanceResponse,
)
from app.services.case_governance import evidence_manifest_sha256, record_governance_event
from app.services.expert_ops import remediation_sla

SessionFactory = Callable[[], object]


class GovernanceViolation(ValueError):
    """A requested governance transition violates the auditable state machine."""


_EVIDENCE_TRANSITIONS = {
    "unreviewed": {"in_review", "accepted", "rejected"},
    "in_review": {"unreviewed", "accepted", "rejected"},
    "rejected": {"in_review"},
    "accepted": {"in_review"},
}

_REMEDIATION_TRANSITIONS = {
    "open": {"in_progress", "blocked"},
    "in_progress": {"open", "blocked", "resolved"},
    "blocked": {"open", "in_progress", "resolved"},
    "resolved": {"in_progress", "closed"},
    "closed": set(),
}


def _evidence_response(row: EvidenceItem) -> EvidenceResponse:
    return EvidenceResponse(
        tenant_id=row.tenant_id,
        campaign_id=row.campaign_id,
        run_id=row.run_id,
        evidence_type=row.evidence_type,
        source=row.source,
        title=row.title,
        sha256=row.sha256,
        technique_id=row.technique_id,
        notes=row.notes,
        evidence_id=row.id,
        manifest_sha256=row.manifest_sha256 or evidence_manifest_sha256(row),
        review_status=row.review_status,
        reviewer=row.reviewer,
        reviewed_at=row.reviewed_at,
        created_at=row.created_at,
    )


def review_evidence(
    evidence_id: str,
    request: EvidenceReviewUpdate,
    session_factory: SessionFactory,
) -> EvidenceResponse:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        row = (
            tenant_query(session.query(EvidenceItem), EvidenceItem, tenant_id)
            .filter(EvidenceItem.id == evidence_id)
            .first()
        )
        if row is None:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        if request.review_status != row.review_status and request.review_status not in _EVIDENCE_TRANSITIONS.get(
            row.review_status, set()
        ):
            raise GovernanceViolation(
                f"evidence transition {row.review_status!r} -> {request.review_status!r} is not allowed"
            )
        row.review_status = request.review_status
        row.reviewer = current_actor()
        row.reviewed_at = datetime.now(timezone.utc)
        if request.notes:
            row.notes = redact_text(request.notes)
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "evidence.reviewed",
                f"Evidence {row.title} marked {row.review_status}.",
                {"evidence_id": row.id, "status": row.review_status},
            )
        session.commit()
        session.refresh(row)
    return _evidence_response(row)


def update_remediation(
    remediation_id: str,
    request: RemediationLifecycleUpdate,
    session_factory: SessionFactory,
) -> RemediationResponse:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        row = (
            tenant_query(session.query(RemediationItem), RemediationItem, tenant_id)
            .filter(RemediationItem.id == remediation_id)
            .first()
        )
        if row is None:
            raise KeyError(f"Unknown remediation: {remediation_id}")
        if request.status != row.status and request.status not in _REMEDIATION_TRANSITIONS.get(row.status, set()):
            raise GovernanceViolation(f"remediation transition {row.status!r} -> {request.status!r} is not allowed")
        row.status = request.status
        row.updated_at = utcnow()
        if request.note:
            row.recommendation = (
                f"{row.recommendation}\nLifecycle note ({current_actor()}): {redact_text(request.note)}"
            )
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "remediation.lifecycle_changed",
                f"Remediation {row.finding_title} moved to {row.status}.",
                {"remediation_id": row.id, "status": row.status},
            )
        session.commit()
        session.refresh(row)
    return RemediationResponse(
        tenant_id=row.tenant_id,
        campaign_id=row.campaign_id,
        finding_title=row.finding_title,
        technique_id=row.technique_id,
        recommendation=row.recommendation,
        owner=row.owner,
        priority=row.priority,
        due_date=row.due_date,
        remediation_id=row.id,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _acceptance_status(row: RiskAcceptance) -> str:
    if row.status == "revoked":
        return "revoked"
    try:
        return "expired" if date.fromisoformat(row.expires_on) < date.today() else "active"
    except ValueError:
        return "expired"


def _acceptance_response(row: RiskAcceptance) -> RiskAcceptanceResponse:
    return RiskAcceptanceResponse(
        tenant_id=row.tenant_id,
        campaign_id=row.campaign_id,
        remediation_id=row.remediation_id,
        technique_id=row.technique_id,
        finding_title=row.finding_title,
        rationale=row.rationale,
        approver=row.approver,
        expires_on=row.expires_on,
        acceptance_id=row.id,
        status=_acceptance_status(row),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def create_risk_acceptance(request: RiskAcceptanceCreate, session_factory: SessionFactory) -> RiskAcceptanceResponse:
    try:
        expires_on = date.fromisoformat(request.expires_on)
    except ValueError as exc:
        raise GovernanceViolation("expires_on must be an ISO date") from exc
    if expires_on <= date.today():
        raise GovernanceViolation("expires_on must be in the future")
    tenant_id = current_tenant_id()
    now = utcnow()
    row = RiskAcceptance(
        id=str(uuid4()),
        tenant_id=tenant_id,
        campaign_id=request.campaign_id,
        remediation_id=request.remediation_id,
        technique_id=request.technique_id,
        finding_title=request.finding_title,
        rationale=request.rationale,
        approver=current_actor(),
        expires_on=request.expires_on,
        status="active",
        created_at=now,
        updated_at=now,
    )
    with session_factory() as session:
        if (
            request.campaign_id
            and tenant_query(session.query(Campaign), Campaign, tenant_id)
            .filter(Campaign.id == request.campaign_id)
            .first() is None
        ):
            raise KeyError(f"Unknown campaign: {request.campaign_id}")
        if (
            request.remediation_id
            and tenant_query(session.query(RemediationItem), RemediationItem, tenant_id)
            .filter(RemediationItem.id == request.remediation_id)
            .first() is None
        ):
            raise KeyError(f"Unknown remediation: {request.remediation_id}")
        session.add(row)
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "risk.acceptance_created",
                f"Risk acceptance created through {row.expires_on}.",
                {"acceptance_id": row.id, "remediation_id": row.remediation_id},
            )
        session.commit()
        session.refresh(row)
    return _acceptance_response(row)


def list_risk_acceptances(session_factory: SessionFactory) -> list[RiskAcceptanceResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = (
            tenant_query(session.query(RiskAcceptance), RiskAcceptance, tenant_id)
            .order_by(RiskAcceptance.expires_on.asc())
            .all()
        )
    return [_acceptance_response(row) for row in rows]


def coverage_scorecard(session_factory: SessionFactory) -> CoverageScorecard:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        runs = tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id).all()
        acceptances = tenant_query(session.query(RiskAcceptance), RiskAcceptance, tenant_id).all()
    expected: set[str] = set()
    gaps: set[str] = set()
    for run in runs:
        gaps.update(run.gaps or [])
        for finding in run.findings or []:
            if finding.get("technique_id"):
                expected.add(finding["technique_id"])
    expected.update(gaps)
    detected = expected - gaps
    active_acceptances = {
        row.technique_id for row in acceptances if row.technique_id and _acceptance_status(row) == "active"
    }
    open_gaps = len(gaps - active_acceptances)
    coverage = (len(detected) / len(expected) * 100) if expected else 0.0
    effective_denominator = max(len(expected) - len(active_acceptances), 1)
    effective = min(100.0, len(detected) / effective_denominator * 100)
    return CoverageScorecard(
        expected_techniques=len(expected),
        detected_techniques=len(detected),
        open_gaps=open_gaps,
        accepted_risks=len(active_acceptances),
        coverage_percent=round(coverage, 2),
        effective_coverage_percent=round(effective, 2),
    )


def executive_kpis(session_factory: SessionFactory) -> ExecutiveKpis:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        runs = (
            tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id)
            .order_by(AssessmentRun.created_at.desc())
            .all()
        )
        remediations = tenant_query(session.query(RemediationItem), RemediationItem, tenant_id).all()
        evidence = tenant_query(session.query(EvidenceItem), EvidenceItem, tenant_id).all()
        acceptances = tenant_query(session.query(RiskAcceptance), RiskAcceptance, tenant_id).all()
    scorecard = coverage_scorecard(session_factory)
    latest_risk = runs[0].risk_score if runs else 0.0
    overdue = sum(1 for item in remediation_sla(session_factory) if item.state == "overdue")
    open_critical = sum(
        1 for item in remediations if item.priority == "critical" and item.status not in {"closed", "resolved"}
    )
    expiring_cutoff = date.today() + timedelta(days=30)
    expiring = 0
    for item in acceptances:
        if _acceptance_status(item) != "active":
            continue
        try:
            expiring += int(date.today() <= date.fromisoformat(item.expires_on) <= expiring_cutoff)
        except ValueError:
            continue
    backlog = sum(1 for item in evidence if item.review_status in {"unreviewed", "in_review"})
    return ExecutiveKpis(
        risk_score=round(latest_risk, 2),
        detection_coverage_percent=scorecard.coverage_percent,
        effective_coverage_percent=scorecard.effective_coverage_percent,
        open_critical_findings=open_critical,
        overdue_remediations=overdue,
        expiring_acceptances=expiring,
        evidence_review_backlog=backlog,
    )
