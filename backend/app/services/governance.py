from datetime import date, datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from app.db.models import (
    AssessmentRun,
    Campaign,
    CampaignTransition,
    EvidenceItem,
    EvidenceReviewEvent,
    RemediationItem,
    RemediationTransition,
    RiskAcceptance,
    utcnow,
)
from app.schemas.contracts import (
    CampaignLifecycleUpdate,
    CampaignResponse,
    CoverageScorecard,
    EvidenceResponse,
    EvidenceReviewUpdate,
    ExecutiveKpis,
    RemediationLifecycleUpdate,
    RemediationResponse,
    RiskAcceptanceCreate,
    RiskAcceptanceResponse,
)
from app.services.expert_ops import remediation_sla

SessionFactory = Callable[[], object]


class GovernanceViolation(ValueError):
    """A requested governance transition violates the auditable state machine."""


_CASE_TRANSITIONS = {
    "active": {"in_review", "contained", "closed", "archived"},
    "in_review": {"active", "contained", "closed", "archived"},
    "contained": {"in_review", "closed", "archived"},
    "closed": {"archived"},
    "archived": set(),
}

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
        campaign_id=row.campaign_id,
        run_id=row.run_id,
        evidence_type=row.evidence_type,
        source=row.source,
        title=row.title,
        sha256=row.sha256,
        technique_id=row.technique_id,
        notes=row.notes,
        evidence_id=row.id,
        review_status=row.review_status,
        reviewer=row.reviewer,
        reviewed_at=row.reviewed_at,
        created_at=row.created_at,
    )


def _remediation_response(row: RemediationItem) -> RemediationResponse:
    return RemediationResponse(
        campaign_id=row.campaign_id,
        finding_title=row.finding_title,
        technique_id=row.technique_id,
        recommendation=row.recommendation,
        owner=row.owner,
        priority=row.priority,
        due_date=row.due_date,
        remediation_id=row.id,
        status=row.status,
        verification_evidence_id=row.verification_evidence_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def update_campaign(
    campaign_id: str,
    request: CampaignLifecycleUpdate,
    session_factory: SessionFactory,
) -> CampaignResponse:
    with session_factory() as session:
        row = session.get(Campaign, campaign_id)
        if row is None:
            raise KeyError(f"Unknown campaign: {campaign_id}")
        if request.status != row.status and request.status not in _CASE_TRANSITIONS.get(row.status, set()):
            raise GovernanceViolation(f"case transition {row.status!r} -> {request.status!r} is not allowed")
        previous_status = row.status
        if previous_status != request.status:
            row.status = request.status
            session.add(
                CampaignTransition(
                    campaign_id=row.id,
                    from_status=previous_status,
                    to_status=request.status,
                    actor=request.actor,
                    note=request.note,
                )
            )
        elif request.note:
            session.add(
                CampaignTransition(
                    campaign_id=row.id,
                    from_status=previous_status,
                    to_status=previous_status,
                    actor=request.actor,
                    note=request.note,
                )
            )
        row.updated_at = utcnow()
        session.commit()
        session.refresh(row)
    return CampaignResponse(
        campaign_id=row.id,
        name=row.name,
        objective=row.objective,
        owner=row.owner,
        scope_snapshot=row.scope_snapshot,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def review_evidence(
    evidence_id: str,
    request: EvidenceReviewUpdate,
    session_factory: SessionFactory,
) -> EvidenceResponse:
    with session_factory() as session:
        row = session.get(EvidenceItem, evidence_id)
        if row is None:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        if request.review_status != row.review_status and request.review_status not in _EVIDENCE_TRANSITIONS.get(
            row.review_status, set()
        ):
            raise GovernanceViolation(
                f"evidence transition {row.review_status!r} -> {request.review_status!r} is not allowed"
            )
        previous_status = row.review_status
        row.review_status = request.review_status
        row.reviewer = request.reviewer
        row.reviewed_at = datetime.now(timezone.utc)
        if request.notes:
            row.notes = request.notes
        if previous_status != request.review_status:
            session.add(
                EvidenceReviewEvent(
                    evidence_id=row.id,
                    from_status=previous_status,
                    to_status=request.review_status,
                    reviewer=request.reviewer,
                    notes=request.notes,
                )
            )
        session.commit()
        session.refresh(row)
    return _evidence_response(row)


def update_remediation(
    remediation_id: str,
    request: RemediationLifecycleUpdate,
    session_factory: SessionFactory,
) -> RemediationResponse:
    with session_factory() as session:
        row = session.get(RemediationItem, remediation_id)
        if row is None:
            raise KeyError(f"Unknown remediation: {remediation_id}")
        if request.status != row.status and request.status not in _REMEDIATION_TRANSITIONS.get(row.status, set()):
            raise GovernanceViolation(f"remediation transition {row.status!r} -> {request.status!r} is not allowed")

        evidence_id = request.verification_evidence_id or row.verification_evidence_id
        if request.status in {"resolved", "closed"}:
            if not evidence_id:
                raise GovernanceViolation("resolved and closed remediations require accepted verification evidence")
            evidence = session.get(EvidenceItem, evidence_id)
            if evidence is None:
                raise KeyError(f"Unknown verification evidence: {evidence_id}")
            if evidence.review_status != "accepted":
                raise GovernanceViolation("verification evidence must be accepted before remediation closure")
            if row.technique_id and evidence.technique_id and row.technique_id != evidence.technique_id:
                raise GovernanceViolation("verification evidence technique does not match the remediation")
        elif request.verification_evidence_id:
            raise GovernanceViolation("verification evidence may only be attached when resolving or closing")

        previous_status = row.status
        row.status = request.status
        row.verification_evidence_id = evidence_id
        row.updated_at = utcnow()
        if previous_status != request.status or request.note:
            session.add(
                RemediationTransition(
                    remediation_id=row.id,
                    from_status=previous_status,
                    to_status=request.status,
                    actor=request.actor,
                    note=request.note,
                )
            )
        session.commit()
        session.refresh(row)
    return _remediation_response(row)


def _acceptance_status(row: RiskAcceptance) -> str:
    if row.status == "revoked":
        return "revoked"
    try:
        return "expired" if date.fromisoformat(row.expires_on) < date.today() else "active"
    except ValueError:
        return "expired"


def _acceptance_response(row: RiskAcceptance) -> RiskAcceptanceResponse:
    return RiskAcceptanceResponse(
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
    expiration = date.fromisoformat(request.expires_on)
    if expiration < date.today():
        raise GovernanceViolation("risk acceptance expiration must not be in the past")
    now = utcnow()
    row = RiskAcceptance(
        id=str(uuid4()),
        campaign_id=request.campaign_id,
        remediation_id=request.remediation_id,
        technique_id=request.technique_id,
        finding_title=request.finding_title,
        rationale=request.rationale,
        approver=request.approver,
        expires_on=request.expires_on,
        status="active",
        created_at=now,
        updated_at=now,
    )
    with session_factory() as session:
        if request.campaign_id and session.get(Campaign, request.campaign_id) is None:
            raise KeyError(f"Unknown campaign: {request.campaign_id}")
        remediation = None
        if request.remediation_id:
            remediation = session.get(RemediationItem, request.remediation_id)
            if remediation is None:
                raise KeyError(f"Unknown remediation: {request.remediation_id}")
            if request.campaign_id and remediation.campaign_id != request.campaign_id:
                raise GovernanceViolation("remediation and campaign must belong to the same case")
            if not request.technique_id:
                row.technique_id = remediation.technique_id
        duplicate_query = session.query(RiskAcceptance).filter(RiskAcceptance.status == "active")
        if row.technique_id and duplicate_query.filter_by(technique_id=row.technique_id).first() is not None:
            raise GovernanceViolation("an active risk acceptance already exists for this technique")
        if row.remediation_id and duplicate_query.filter_by(remediation_id=row.remediation_id).first() is not None:
            raise GovernanceViolation("an active risk acceptance already exists for this remediation")
        session.add(row)
        session.commit()
        session.refresh(row)
    return _acceptance_response(row)


def list_risk_acceptances(session_factory: SessionFactory) -> list[RiskAcceptanceResponse]:
    with session_factory() as session:
        rows = session.query(RiskAcceptance).order_by(RiskAcceptance.expires_on.asc()).all()
    return [_acceptance_response(row) for row in rows]


def coverage_scorecard(session_factory: SessionFactory) -> CoverageScorecard:
    with session_factory() as session:
        runs = session.query(AssessmentRun).all()
        acceptances = session.query(RiskAcceptance).all()
        remediations = session.query(RemediationItem).all()
    expected: set[str] = set()
    gaps: set[str] = set()
    for run in runs:
        gaps.update(run.gaps or [])
        for finding in run.findings or []:
            if finding.get("technique_id"):
                expected.add(finding["technique_id"])
    expected.update(gaps)
    detected = expected - gaps
    accepted_techniques = {
        row.technique_id for row in acceptances if row.technique_id and _acceptance_status(row) == "active"
    }
    remediation_by_id = {row.id: row for row in remediations}
    accepted_techniques.update(
        remediation_by_id[row.remediation_id].technique_id
        for row in acceptances
        if row.remediation_id
        and row.remediation_id in remediation_by_id
        and row.technique_id is None
        and remediation_by_id[row.remediation_id].technique_id
        and _acceptance_status(row) == "active"
    )
    open_gaps = len(gaps - accepted_techniques)
    coverage = (len(detected) / len(expected) * 100) if expected else 0.0
    effective_denominator = max(len(expected) - len(accepted_techniques), 1)
    effective = min(100.0, len(detected) / effective_denominator * 100)
    return CoverageScorecard(
        expected_techniques=len(expected),
        detected_techniques=len(detected),
        open_gaps=open_gaps,
        accepted_risks=len(accepted_techniques),
        coverage_percent=round(coverage, 2),
        effective_coverage_percent=round(effective, 2),
    )


def executive_kpis(session_factory: SessionFactory) -> ExecutiveKpis:
    with session_factory() as session:
        runs = session.query(AssessmentRun).order_by(AssessmentRun.created_at.desc()).all()
        remediations = session.query(RemediationItem).all()
        evidence = session.query(EvidenceItem).all()
        acceptances = session.query(RiskAcceptance).all()
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
