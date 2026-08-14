from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Callable
from uuid import NAMESPACE_URL, uuid4, uuid5

from app.core.ownership import tenant_query
from app.core.redaction import redact_metadata, redact_text
from app.core.request_context import current_actor, current_tenant_id
from app.db.models import (
    ApprovalDelegation,
    Campaign,
    CaseDecisionEvent,
    EvidenceItem,
    Membership,
    RemediationItem,
    RemediationVerificationEvidence,
    RiskAcceptance,
    User,
    utcnow,
)
from app.schemas.contracts import (
    ApprovalDelegationCreate,
    ApprovalDelegationResponse,
    CaseDecisionEventResponse,
    CaseDecisionTimelineResponse,
    CaseExportFixture,
    RemediationEscalationDraft,
    RemediationSlaEscalation,
    RemediationSlaItem,
    RemediationVerificationEvidenceResponse,
    RiskAcceptanceExpiryReminder,
    SlaClock,
)
from app.services.case_governance import evidence_manifest_sha256, record_governance_event

SessionFactory = Callable[[], object]

SLA_POLICY_VERSION = "2.0"
EXPIRY_REMINDER_POLICY_VERSION = "1.0"
EXPIRY_REMINDER_WINDOW_DAYS = 14
MAX_DELEGATION_DAYS = 7
CASE_COMPLIANCE_MAX_ITEMS = 512
DECISION_TIMELINE_MAX_EVENTS = 1000
DELEGATION_MAX_ITEMS = 256
VERIFICATION_EVIDENCE_MAX_ITEMS = 512
GENESIS_DIGEST = "0" * 64
_SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 60}
_MANAGE_CASES_ROLES = {"platform_admin", "tenant_admin", "analyst", "remediation_manager"}


def _aware(value: datetime, fallback: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=fallback.tzinfo or timezone.utc)
    return value


def _due_at(row: RemediationItem, start: datetime) -> tuple[date, datetime, int]:
    target_days = _SLA_DAYS.get(row.priority, _SLA_DAYS["medium"])
    due_date = date.fromisoformat(row.due_date) if row.due_date else start.date() + timedelta(days=target_days)
    if row.due_date:
        due_at = datetime.combine(due_date, time.max, tzinfo=timezone.utc)
    else:
        due_at = start + timedelta(days=target_days)
    return due_date, due_at, target_days


def _sla_clock(row: RemediationItem, now: datetime) -> tuple[SlaClock, date, int]:
    start = _aware(row.created_at or now, now)
    due_date, due_at, target_days = _due_at(row, start)
    if row.status in {"resolved", "closed"}:
        state = "closed"
    elif due_at < now:
        state = "overdue"
    elif (due_at - now).total_seconds() <= max(2 * 86400, target_days * 86400 // 5):
        state = "due_soon"
    else:
        state = "on_track"
    elapsed_seconds = max(0, int((min(now, due_at) - start).total_seconds()))
    remaining_seconds = int((due_at - now).total_seconds())
    return (
        SlaClock(
            policy_version=SLA_POLICY_VERSION,
            started_at=start,
            due_at=due_at,
            elapsed_seconds=elapsed_seconds,
            remaining_seconds=remaining_seconds,
            paused_seconds=0,
            state=state,
        ),
        due_date,
        target_days,
    )


def remediation_sla(session_factory: SessionFactory, *, now: datetime | None = None) -> list[RemediationSlaItem]:
    tenant_id = current_tenant_id()
    effective_now = now or utcnow()
    with session_factory() as session:
        rows = (
            tenant_query(session.query(RemediationItem), RemediationItem, tenant_id)
            .order_by(RemediationItem.updated_at.desc(), RemediationItem.id.asc())
            .limit(CASE_COMPLIANCE_MAX_ITEMS)
            .all()
        )
    results: list[RemediationSlaItem] = []
    for row in rows:
        clock, due_date, target_days = _sla_clock(row, effective_now)
        results.append(
            RemediationSlaItem(
                remediation_id=row.id,
                finding_title=row.finding_title,
                priority=row.priority,
                status=row.status,
                owner=row.owner,
                assigned_to=row.assigned_to,
                due_date=due_date.isoformat(),
                target_days=target_days,
                state=clock.state,
                clock=clock,
            )
        )
    return results


def _draft_id(tenant_id: str, remediation_id: str, state: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"redpath:{SLA_POLICY_VERSION}:{tenant_id}:{remediation_id}:{state}"))


def remediation_escalations(session_factory: SessionFactory) -> list[RemediationSlaEscalation]:
    escalations: list[RemediationSlaEscalation] = []
    for item in remediation_sla(session_factory):
        if item.state not in {"due_soon", "overdue"}:
            continue
        level = (
            "leadership_review"
            if item.state == "overdue" and item.priority in {"critical", "high"}
            else "manager_review"
        )
        action = (
            "Review overdue remediation ownership and approve a time-bounded exception or recovery plan."
            if item.state == "overdue"
            else "Notify the assigned owner and validate the remediation plan before the SLA window closes."
        )
        escalations.append(
            RemediationSlaEscalation(
                tenant_id=current_tenant_id(),
                remediation_id=item.remediation_id,
                assigned_to=item.assigned_to,
                state=item.state,
                escalation_level=level,
                policy_version=SLA_POLICY_VERSION,
                recommended_action=action,
                draft_id=_draft_id(current_tenant_id(), item.remediation_id, item.state),
                notification_mode="mock",
                requires_opt_in=True,
            )
        )
    return escalations


def remediation_escalation_drafts(session_factory: SessionFactory) -> list[RemediationEscalationDraft]:
    now = utcnow()
    drafts: list[RemediationEscalationDraft] = []
    for escalation in remediation_escalations(session_factory):
        recipient = escalation.assigned_to or "case-owner"
        drafts.append(
            RemediationEscalationDraft(
                draft_id=escalation.draft_id,
                tenant_id=escalation.tenant_id,
                remediation_id=escalation.remediation_id,
                recipient_actor=recipient,
                state=escalation.state,
                escalation_level=escalation.escalation_level,
                policy_version=SLA_POLICY_VERSION,
                notification_mode="mock",
                requires_opt_in=True,
                sent=False,
                subject=f"Case remediation {escalation.state} SLA review",
                body=redact_text(escalation.recommended_action),
                generated_at=now,
            )
        )
    return drafts


def risk_acceptance_expiry_reminders(
    session_factory: SessionFactory,
    *,
    window_days: int = EXPIRY_REMINDER_WINDOW_DAYS,
    today: date | None = None,
) -> list[RiskAcceptanceExpiryReminder]:
    if window_days < 0 or window_days > 90:
        raise ValueError("expiry reminder window must be between 0 and 90 days")
    tenant_id = current_tenant_id()
    effective_today = today or date.today()
    with session_factory() as session:
        rows = (
            tenant_query(session.query(RiskAcceptance), RiskAcceptance, tenant_id)
            .filter(RiskAcceptance.status == "active", RiskAcceptance.approval_status == "approved")
            .order_by(RiskAcceptance.expires_on.asc(), RiskAcceptance.id.asc())
            .limit(256)
            .all()
        )
    reminders: list[RiskAcceptanceExpiryReminder] = []
    for row in rows:
        try:
            expires_on = date.fromisoformat(row.expires_on)
        except ValueError:
            continue
        days_remaining = (expires_on - effective_today).days
        if days_remaining > window_days:
            continue
        reminders.append(
            RiskAcceptanceExpiryReminder(
                reminder_id=str(uuid5(NAMESPACE_URL, f"redpath:expiry:{tenant_id}:{row.id}:{row.expires_on}")),
                tenant_id=row.tenant_id,
                acceptance_id=row.id,
                approver=row.approver,
                expires_on=row.expires_on,
                days_remaining=days_remaining,
                urgency="expired" if days_remaining < 0 else "expiring",
                policy_version=EXPIRY_REMINDER_POLICY_VERSION,
                notification_mode="mock",
                requires_opt_in=True,
                sent=False,
                generated_at=utcnow(),
            )
        )
    return reminders


def _decision_digest(
    *,
    previous_digest: str,
    tenant_id: str,
    case_id: str,
    resource_type: str,
    resource_id: str,
    decision_type: str,
    actor: str,
    previous_state: str | None,
    new_state: str | None,
    reason: str,
    metadata: dict[str, Any],
    created_at: datetime,
) -> str:
    normalized_created_at = (
        created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=timezone.utc)
    )
    canonical = json.dumps(
        {
            "previous_digest": previous_digest,
            "tenant_id": tenant_id,
            "case_id": case_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "decision_type": decision_type,
            "actor": actor,
            "previous_state": previous_state,
            "new_state": new_state,
            "reason": reason,
            "metadata": metadata,
            "created_at": normalized_created_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_decision_event(
    session: object,
    case_id: str,
    resource_type: str,
    resource_id: str,
    decision_type: str,
    previous_state: str | None,
    new_state: str | None,
    reason: str = "",
    metadata: dict[str, Any] | None = None,
) -> CaseDecisionEvent:
    tenant_id = current_tenant_id()
    previous = (
        tenant_query(session.query(CaseDecisionEvent), CaseDecisionEvent, tenant_id)
        .filter(CaseDecisionEvent.case_id == case_id)
        .order_by(CaseDecisionEvent.created_at.desc(), CaseDecisionEvent.id.desc())
        .first()
    )
    now = utcnow()
    redacted_reason = redact_text(reason)
    redacted_metadata = redact_metadata(metadata or {})
    previous_digest = previous.digest if previous else GENESIS_DIGEST
    digest = _decision_digest(
        previous_digest=previous_digest,
        tenant_id=tenant_id,
        case_id=case_id,
        resource_type=resource_type,
        resource_id=resource_id,
        decision_type=decision_type,
        actor=current_actor(),
        previous_state=previous_state,
        new_state=new_state,
        reason=redacted_reason,
        metadata=redacted_metadata,
        created_at=now,
    )
    event = CaseDecisionEvent(
        id=str(uuid4()),
        tenant_id=tenant_id,
        case_id=case_id,
        resource_type=resource_type,
        resource_id=resource_id,
        decision_type=decision_type,
        actor=current_actor(),
        previous_state=previous_state,
        new_state=new_state,
        reason=redacted_reason,
        metadata_json=redacted_metadata,
        previous_digest=previous_digest,
        digest=digest,
        created_at=now,
    )
    session.add(event)
    return event


def _event_response(row: CaseDecisionEvent) -> CaseDecisionEventResponse:
    return CaseDecisionEventResponse(
        event_id=row.id,
        tenant_id=row.tenant_id,
        case_id=row.case_id,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        decision_type=row.decision_type,
        actor=row.actor,
        previous_state=row.previous_state,
        new_state=row.new_state,
        reason=row.reason,
        metadata=dict(row.metadata_json or {}),
        previous_digest=row.previous_digest,
        digest=row.digest,
        created_at=row.created_at,
    )


def _recompute_event_digest(row: CaseDecisionEvent) -> str:
    return _decision_digest(
        previous_digest=row.previous_digest,
        tenant_id=row.tenant_id,
        case_id=row.case_id,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        decision_type=row.decision_type,
        actor=row.actor,
        previous_state=row.previous_state,
        new_state=row.new_state,
        reason=row.reason,
        metadata=dict(row.metadata_json or {}),
        created_at=row.created_at,
    )


def list_decision_timeline(case_id: str, session_factory: SessionFactory) -> CaseDecisionTimelineResponse:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        case = tenant_query(session.query(Campaign), Campaign, tenant_id).filter(Campaign.id == case_id).first()
        if case is None:
            raise KeyError(f"Unknown case: {case_id}")
        rows = (
            tenant_query(session.query(CaseDecisionEvent), CaseDecisionEvent, tenant_id)
            .filter(CaseDecisionEvent.case_id == case_id)
            .order_by(CaseDecisionEvent.created_at.asc(), CaseDecisionEvent.id.asc())
            .limit(DECISION_TIMELINE_MAX_EVENTS)
            .all()
        )
    expected = GENESIS_DIGEST
    valid = True
    for row in rows:
        if row.previous_digest != expected or _recompute_event_digest(row) != row.digest:
            valid = False
        expected = row.digest
    return CaseDecisionTimelineResponse(
        case_id=case_id,
        tenant_id=tenant_id,
        events=[_event_response(row) for row in rows],
        integrity_valid=valid,
        tail_digest=expected,
    )


def record_verification_evidence(
    remediation_id: str,
    evidence_id: str,
    manifest_sha256: str,
    summary: str,
    session_factory: SessionFactory,
) -> RemediationVerificationEvidenceResponse:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        remediation = (
            tenant_query(session.query(RemediationItem), RemediationItem, tenant_id)
            .filter(RemediationItem.id == remediation_id)
            .first()
        )
        if remediation is None:
            raise KeyError(f"Unknown remediation: {remediation_id}")
        if remediation.status not in {"resolved", "closed"}:
            raise ValueError("verification evidence requires a resolved or closed remediation")
        if not remediation.campaign_id:
            raise ValueError("verification evidence requires a case-linked remediation")
        evidence = (
            tenant_query(session.query(EvidenceItem), EvidenceItem, tenant_id)
            .filter(EvidenceItem.id == evidence_id)
            .first()
        )
        if evidence is None:
            raise KeyError(f"Unknown evidence: {evidence_id}")
        if evidence.campaign_id != remediation.campaign_id:
            raise ValueError("verification evidence must belong to the remediation case")
        if evidence.review_status != "accepted" or evidence.custody_status != "verified":
            raise ValueError("verification evidence must be accepted and custody verified")
        actual_manifest = evidence.manifest_sha256 or evidence_manifest_sha256(evidence)
        if manifest_sha256.lower() != actual_manifest:
            raise ValueError("verification evidence manifest does not match immutable evidence")
        now = utcnow()
        row = RemediationVerificationEvidence(
            id=str(uuid4()),
            tenant_id=tenant_id,
            case_id=remediation.campaign_id,
            remediation_id=remediation.id,
            evidence_id=evidence.id,
            manifest_sha256=actual_manifest,
            summary=redact_text(summary),
            recorded_by=current_actor(),
            created_at=now,
        )
        session.add(row)
        record_governance_event(
            session,
            remediation.campaign_id,
            "remediation.verification_evidence_recorded",
            f"Verification evidence recorded for {remediation.finding_title}.",
            {"remediation_id": remediation.id, "evidence_id": evidence.id, "manifest_sha256": actual_manifest},
        )
        record_decision_event(
            session,
            remediation.campaign_id,
            "remediation",
            remediation.id,
            "verification_evidence_recorded",
            remediation.verification_status,
            "verified",
            summary,
            {"evidence_id": evidence.id, "manifest_sha256": actual_manifest},
        )
        session.commit()
        session.refresh(row)
    return RemediationVerificationEvidenceResponse(
        evidence_record_id=row.id,
        tenant_id=row.tenant_id,
        case_id=row.case_id,
        remediation_id=row.remediation_id,
        evidence_id=row.evidence_id,
        manifest_sha256=row.manifest_sha256,
        summary=row.summary,
        recorded_by=row.recorded_by,
        created_at=row.created_at,
    )


def list_verification_evidence(
    remediation_id: str, session_factory: SessionFactory
) -> list[RemediationVerificationEvidenceResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        remediation = (
            tenant_query(session.query(RemediationItem), RemediationItem, tenant_id)
            .filter(RemediationItem.id == remediation_id)
            .first()
        )
        if remediation is None:
            raise KeyError(f"Unknown remediation: {remediation_id}")
        rows = (
            tenant_query(session.query(RemediationVerificationEvidence), RemediationVerificationEvidence, tenant_id)
            .filter(RemediationVerificationEvidence.remediation_id == remediation_id)
            .order_by(RemediationVerificationEvidence.created_at.asc(), RemediationVerificationEvidence.id.asc())
            .limit(VERIFICATION_EVIDENCE_MAX_ITEMS)
            .all()
        )
    return [
        RemediationVerificationEvidenceResponse(
            evidence_record_id=row.id,
            tenant_id=row.tenant_id,
            case_id=row.case_id,
            remediation_id=row.remediation_id,
            evidence_id=row.evidence_id,
            manifest_sha256=row.manifest_sha256,
            summary=row.summary,
            recorded_by=row.recorded_by,
            created_at=row.created_at,
        )
        for row in rows
    ]


def _delegation_status(row: ApprovalDelegation, now: datetime) -> str:
    if row.status == "revoked":
        return "revoked"
    expires_at = _aware(row.expires_at, now)
    return "expired" if now >= expires_at else "active"


def _delegation_response(row: ApprovalDelegation, now: datetime | None = None) -> ApprovalDelegationResponse:
    effective_now = now or utcnow()
    return ApprovalDelegationResponse(
        delegation_id=row.id,
        tenant_id=row.tenant_id,
        campaign_id=row.campaign_id,
        delegator_username=row.delegator_username,
        delegate_username=row.delegate_username,
        starts_at=row.starts_at,
        expires_at=row.expires_at,
        status=_delegation_status(row, effective_now),
        created_by=row.created_by,
        revoked_by=row.revoked_by,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def create_approval_delegation(
    request: ApprovalDelegationCreate,
    session_factory: SessionFactory,
) -> ApprovalDelegationResponse:
    tenant_id = current_tenant_id()
    actor = current_actor()
    now = utcnow()
    starts_at = request.starts_at or now
    starts_at = _aware(starts_at, now)
    expires_at = _aware(request.expires_at, now)
    if expires_at <= starts_at:
        raise ValueError("delegation expiry must be after its start")
    if expires_at - starts_at > timedelta(days=MAX_DELEGATION_DAYS):
        raise ValueError("delegation cannot exceed seven days")
    if starts_at > now + timedelta(hours=24):
        raise ValueError("delegation cannot start more than 24 hours in the future")
    if request.delegate_username == actor:
        raise ValueError("delegation target must differ from the delegating actor")
    with session_factory() as session:
        if request.campaign_id and tenant_query(session.query(Campaign), Campaign, tenant_id).filter(
            Campaign.id == request.campaign_id
        ).first() is None:
            raise KeyError(f"Unknown campaign: {request.campaign_id}")
        delegate = tenant_query(session.query(User), User, tenant_id).filter(
            User.username == request.delegate_username, User.is_active.is_(True)
        ).first()
        if delegate is None:
            raise KeyError(f"Unknown approval delegate: {request.delegate_username}")
        membership = session.query(Membership).filter(
            Membership.user_id == delegate.id,
            Membership.tenant_id == tenant_id,
            Membership.is_active.is_(True),
            Membership.role.in_(_MANAGE_CASES_ROLES),
        ).first()
        if membership is None:
            raise ValueError("approval delegate must hold an active case-management role")
        row = ApprovalDelegation(
            id=str(uuid4()),
            tenant_id=tenant_id,
            campaign_id=request.campaign_id,
            delegator_username=actor,
            delegate_username=delegate.username,
            starts_at=starts_at,
            expires_at=expires_at,
            status="active",
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        if request.campaign_id:
            record_governance_event(
                session,
                request.campaign_id,
                "approval.delegation_created",
                f"Approval delegation granted to {delegate.username}.",
                {"delegation_id": row.id, "expires_at": expires_at.isoformat()},
            )
            record_decision_event(
                session,
                request.campaign_id,
                "approval_delegation",
                row.id,
                "delegation_created",
                None,
                "active",
                "Approval delegation created.",
                {"delegate_username": delegate.username, "expires_at": expires_at.isoformat()},
            )
        session.commit()
        session.refresh(row)
    return _delegation_response(row, now)


def list_approval_delegations(session_factory: SessionFactory) -> list[ApprovalDelegationResponse]:
    tenant_id = current_tenant_id()
    now = utcnow()
    with session_factory() as session:
        rows = tenant_query(session.query(ApprovalDelegation), ApprovalDelegation, tenant_id).order_by(
            ApprovalDelegation.expires_at.asc(), ApprovalDelegation.id.asc()
        ).limit(DELEGATION_MAX_ITEMS).all()
    return [_delegation_response(row, now) for row in rows]


def revoke_approval_delegation(delegation_id: str, session_factory: SessionFactory) -> ApprovalDelegationResponse:
    tenant_id = current_tenant_id()
    actor = current_actor()
    with session_factory() as session:
        row = tenant_query(session.query(ApprovalDelegation), ApprovalDelegation, tenant_id).filter(
            ApprovalDelegation.id == delegation_id
        ).first()
        if row is None:
            raise KeyError(f"Unknown approval delegation: {delegation_id}")
        if row.status == "revoked":
            raise ValueError("approval delegation is already revoked")
        row.status = "revoked"
        row.revoked_by = actor
        row.revoked_at = utcnow()
        row.updated_at = utcnow()
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "approval.delegation_revoked",
                "Approval delegation revoked.",
                {"delegation_id": row.id},
            )
            record_decision_event(
                session,
                row.campaign_id,
                "approval_delegation",
                row.id,
                "delegation_revoked",
                "active",
                "revoked",
                "Approval delegation revoked.",
                {},
            )
        session.commit()
        session.refresh(row)
    return _delegation_response(row)


def validate_approval_delegation(
    session: object,
    delegation_id: str,
    campaign_id: str | None,
    tenant_id: str,
    actor: str,
) -> ApprovalDelegation:
    row = tenant_query(session.query(ApprovalDelegation), ApprovalDelegation, tenant_id).filter(
        ApprovalDelegation.id == delegation_id
    ).first()
    if row is None:
        raise ValueError("approval delegation is not valid for this tenant")
    now = utcnow()
    starts_at = _aware(row.starts_at, now)
    expires_at = _aware(row.expires_at, now)
    if _delegation_status(row, now) != "active" or not (starts_at <= now < expires_at):
        raise ValueError("approval delegation is not active")
    if row.delegate_username != actor:
        raise ValueError("approval delegation actor mismatch")
    if row.campaign_id and row.campaign_id != campaign_id:
        raise ValueError("approval delegation is not valid for this case")
    return row


def case_export_fixture(export: Any) -> CaseExportFixture:
    payload = {
        "fixture_version": "1.0",
        "tenant_id": export.tenant_id,
        "actor": export.actor,
        "case_id": export.campaign.campaign_id,
        "source_manifest_sha256": export.manifest_sha256,
        "record_counts": {
            "timeline": len(export.timeline),
            "evidence": len(export.evidence),
            "verification_evidence": len(export.verification_evidence),
            "remediations": len(export.remediations),
            "custody_history": len(export.custody_history),
            "governance_history": len(export.governance_history),
            "decision_timeline": len(export.decision_timeline),
            "risk_acceptances": len(export.risk_acceptances),
            "sla_escalations": len(export.sla_escalations),
        },
        "timeline_integrity": export.timeline_integrity,
        "redacted": True,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return CaseExportFixture(
        **payload,
        fixture_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        generated_at=utcnow(),
    )
