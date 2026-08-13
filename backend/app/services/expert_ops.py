from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from app.core.ownership import tenant_query
from app.core.redaction import redact_text
from app.core.request_context import current_actor, current_tenant_id
from app.db.models import AssessmentRun, Campaign, CampaignRunLink, EvidenceItem, RemediationItem, User, utcnow
from app.schemas.contracts import (
    CampaignCreate,
    CampaignExport,
    CampaignResponse,
    CampaignTimelineEvent,
    DetectionTuningItem,
    EvidenceCreate,
    EvidenceManifest,
    EvidenceResponse,
    RemediationAssignmentUpdate,
    RemediationCreate,
    RemediationResponse,
    RemediationSlaEscalation,
    RemediationSlaItem,
    TrendPoint,
)
from app.services.case_governance import (
    evidence_manifest_sha256,
    list_custody_history,
    list_governance_history,
    record_governance_event,
)

SessionFactory = Callable[[], object]


def _campaign_response(row: Campaign) -> CampaignResponse:
    return CampaignResponse(
        tenant_id=row.tenant_id,
        campaign_id=row.id,
        name=row.name,
        objective=row.objective,
        owner=row.owner,
        scope_snapshot=row.scope_snapshot,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def create_campaign(request: CampaignCreate, session_factory: SessionFactory) -> CampaignResponse:
    now = utcnow()
    row = Campaign(
        id=str(uuid4()),
        tenant_id=current_tenant_id(),
        name=request.name,
        objective=request.objective,
        owner=current_actor(),
        scope_snapshot=request.scope_snapshot,
        status="active",
        created_at=now,
        updated_at=now,
    )
    with session_factory() as session:
        session.add(row)
        record_governance_event(session, row.id, "case.created", f"Case {row.name} created.")
        session.commit()
        session.refresh(row)
    return _campaign_response(row)


def list_campaigns(session_factory: SessionFactory) -> list[CampaignResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = tenant_query(session.query(Campaign), Campaign, tenant_id).order_by(Campaign.updated_at.desc()).all()
    return [_campaign_response(row) for row in rows]


def link_run(campaign_id: str, run_id: str, session_factory: SessionFactory) -> None:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        if (
            tenant_query(session.query(Campaign), Campaign, tenant_id)
            .filter(Campaign.id == campaign_id)
            .first()
            is None
        ):
            raise KeyError(f"Unknown campaign: {campaign_id}")
        if (
            tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id)
            .filter(AssessmentRun.id == run_id)
            .first()
            is None
        ):
            raise KeyError(f"Unknown assessment run: {run_id}")
        existing = (
            tenant_query(session.query(CampaignRunLink), CampaignRunLink, tenant_id)
            .filter(CampaignRunLink.campaign_id == campaign_id, CampaignRunLink.run_id == run_id)
            .first()
        )
        if existing is None:
            session.add(CampaignRunLink(campaign_id=campaign_id, run_id=run_id, tenant_id=tenant_id))
            record_governance_event(
                session,
                campaign_id,
                "assessment.linked",
                f"Assessment run {run_id} linked to the case.",
                {"run_id": run_id},
            )
        session.commit()


def create_evidence(request: EvidenceCreate, session_factory: SessionFactory) -> EvidenceResponse:
    tenant_id = current_tenant_id()
    row = EvidenceItem(
        id=str(uuid4()),
        tenant_id=tenant_id,
        campaign_id=request.campaign_id,
        run_id=request.run_id,
        evidence_type=request.evidence_type,
        source=request.source,
        title=request.title,
        sha256=request.sha256,
        technique_id=request.technique_id,
        notes=redact_text(request.notes),
        manifest_sha256=None,
        review_status="unreviewed",
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
            request.run_id
            and tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id)
            .filter(AssessmentRun.id == request.run_id)
            .first() is None
        ):
            raise KeyError(f"Unknown assessment run: {request.run_id}")
        row.manifest_sha256 = evidence_manifest_sha256(row)
        session.add(row)
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "evidence.registered",
                f"Evidence {row.title} registered.",
                {"evidence_id": row.id, "sha256": row.sha256},
            )
        session.commit()
        session.refresh(row)
    return EvidenceResponse(
        **request.model_dump(),
        tenant_id=row.tenant_id,
        evidence_id=row.id,
        manifest_sha256=row.manifest_sha256 or evidence_manifest_sha256(row),
        review_status=row.review_status,
        custody_status=row.custody_status,
        custody_verified_by=row.custody_verified_by,
        custody_verified_at=row.custody_verified_at,
        custody_verification_sha256=row.custody_verification_sha256,
        created_at=row.created_at,
    )


def list_evidence(session_factory: SessionFactory, campaign_id: str | None = None) -> list[EvidenceResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        query = tenant_query(session.query(EvidenceItem), EvidenceItem, tenant_id).order_by(
            EvidenceItem.created_at.desc()
        )
        if campaign_id and session.query(Campaign).filter_by(id=campaign_id, tenant_id=tenant_id).first() is None:
            raise KeyError(f"Unknown campaign: {campaign_id}")
        rows = query.filter_by(campaign_id=campaign_id).all() if campaign_id else query.all()
    return [
        EvidenceResponse(
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
            custody_status=row.custody_status,
            custody_verified_by=row.custody_verified_by,
            custody_verified_at=row.custody_verified_at,
            custody_verification_sha256=row.custody_verification_sha256,
            created_at=row.created_at,
        )
        for row in rows
    ]


def create_remediation(request: RemediationCreate, session_factory: SessionFactory) -> RemediationResponse:
    tenant_id = current_tenant_id()
    now = utcnow()
    row = RemediationItem(
        id=str(uuid4()),
        tenant_id=tenant_id,
        campaign_id=request.campaign_id,
        finding_title=request.finding_title,
        technique_id=request.technique_id,
        recommendation=redact_text(request.recommendation),
        owner=current_actor(),
        assigned_to=request.assigned_to or current_actor(),
        priority=request.priority,
        status="open",
        due_date=request.due_date,
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
        assignee = (
            tenant_query(session.query(User), User, tenant_id)
            .filter(User.username == row.assigned_to, User.is_active.is_(True))
            .first()
        )
        if assignee is None:
            raise KeyError(f"Unknown remediation assignee: {row.assigned_to}")
        row.assigned_to = assignee.username
        session.add(row)
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "remediation.created",
                f"Remediation for {row.finding_title} created.",
                {"remediation_id": row.id, "priority": row.priority},
            )
        session.commit()
        session.refresh(row)
    payload = request.model_dump()
    payload["assigned_to"] = row.assigned_to
    return RemediationResponse(
        **payload,
        tenant_id=row.tenant_id,
        remediation_id=row.id,
        status=row.status,
        verification_status=row.verification_status,
        verified_by=row.verified_by,
        verified_at=row.verified_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def assign_remediation(
    remediation_id: str,
    request: RemediationAssignmentUpdate,
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
        assignee = (
            tenant_query(session.query(User), User, tenant_id)
            .filter(User.username == request.assigned_to, User.is_active.is_(True))
            .first()
        )
        if assignee is None:
            raise KeyError(f"Unknown remediation assignee: {request.assigned_to}")
        row.assigned_to = assignee.username
        row.updated_at = utcnow()
        if row.campaign_id:
            record_governance_event(
                session,
                row.campaign_id,
                "remediation.assigned",
                f"Remediation {row.finding_title} assigned.",
                {"remediation_id": row.id, "assigned_to": row.assigned_to},
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
        assigned_to=row.assigned_to,
        priority=row.priority,
        due_date=row.due_date,
        remediation_id=row.id,
        status=row.status,
        verification_status=row.verification_status,
        verified_by=row.verified_by,
        verified_at=row.verified_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def list_remediations(session_factory: SessionFactory, campaign_id: str | None = None) -> list[RemediationResponse]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        if campaign_id and session.query(Campaign).filter_by(id=campaign_id, tenant_id=tenant_id).first() is None:
            raise KeyError(f"Unknown campaign: {campaign_id}")
        query = (
            tenant_query(session.query(RemediationItem), RemediationItem, tenant_id).order_by(
                RemediationItem.updated_at.desc()
            )
        )
        rows = query.filter_by(campaign_id=campaign_id).all() if campaign_id else query.all()
    return [
        RemediationResponse(
            tenant_id=row.tenant_id,
            campaign_id=row.campaign_id,
            finding_title=row.finding_title,
            technique_id=row.technique_id,
            recommendation=row.recommendation,
            owner=row.owner,
            assigned_to=row.assigned_to,
            priority=row.priority,
            due_date=row.due_date,
            remediation_id=row.id,
            status=row.status,
            verification_status=row.verification_status,
            verified_by=row.verified_by,
            verified_at=row.verified_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


def campaign_timeline(campaign_id: str, session_factory: SessionFactory) -> list[CampaignTimelineEvent]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        if (
            tenant_query(session.query(Campaign), Campaign, tenant_id)
            .filter(Campaign.id == campaign_id)
            .first()
            is None
        ):
            raise KeyError(f"Unknown campaign: {campaign_id}")
        links = (
            tenant_query(session.query(CampaignRunLink), CampaignRunLink, tenant_id)
            .filter(CampaignRunLink.campaign_id == campaign_id)
            .all()
        )
        evidence = (
            tenant_query(session.query(EvidenceItem), EvidenceItem, tenant_id)
            .filter(EvidenceItem.campaign_id == campaign_id)
            .all()
        )
        remediations = (
            tenant_query(session.query(RemediationItem), RemediationItem, tenant_id)
            .filter(RemediationItem.campaign_id == campaign_id)
            .all()
        )
        run_ids = [link.run_id for link in links]
        run_rows = (
            tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id)
            .filter(AssessmentRun.id.in_(run_ids))
            .all()
            if run_ids
            else []
        )
        runs = {row.id: row for row in run_rows}
    events = [
        CampaignTimelineEvent(
            event_type="assessment_run",
            reference_id=run.id,
            title=f"Scenario run: {run.scenario_id}",
            status=run.status,
            occurred_at=run.created_at,
        )
        for run in runs.values()
    ]
    events.extend(
        CampaignTimelineEvent(
            event_type="evidence",
            reference_id=item.id,
            title=item.title,
            status=item.review_status,
            occurred_at=item.created_at,
        )
        for item in evidence
    )
    events.extend(
        CampaignTimelineEvent(
            event_type="remediation",
            reference_id=item.id,
            title=item.finding_title,
            status=item.status,
            occurred_at=item.updated_at,
        )
        for item in remediations
    )
    return sorted(events, key=lambda item: item.occurred_at, reverse=True)


def risk_trend(session_factory: SessionFactory) -> list[TrendPoint]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = (
            tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id)
            .order_by(AssessmentRun.created_at.asc())
            .all()
        )
    buckets: dict[str, list[AssessmentRun]] = defaultdict(list)
    for row in rows:
        period = (row.created_at or datetime.now(timezone.utc)).date().isoformat()
        buckets[period].append(row)
    return [
        TrendPoint(
            period=period,
            average_risk_score=round(sum(row.risk_score for row in values) / len(values), 2),
            average_coverage_percent=round(sum(row.coverage_percent for row in values) / len(values), 2),
            run_count=len(values),
        )
        for period, values in sorted(buckets.items())
    ]


def detection_tuning_queue(session_factory: SessionFactory) -> list[DetectionTuningItem]:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        rows = tenant_query(session.query(AssessmentRun), AssessmentRun, tenant_id).all()
    counts = Counter(gap for row in rows for gap in (row.gaps or []))
    metadata = {
        "T1558.003": (
            "high",
            "Detect unusual service-ticket requests and correlate account risk.",
            ["Windows 4769", "Identity inventory"],
            "lab/fixtures/wazuh_alerts.json",
        ),
        "T1558.004": (
            "high",
            "Detect accounts without Kerberos pre-authentication and correlate identity exposure.",
            ["Windows 4768", "Directory account attributes"],
            "lab/fixtures/ad_observations.json",
        ),
        "T1649": (
            "medium",
            "Detect certificate issuance from risky authentication templates and review enrollment context.",
            ["ADCS audit events", "Certificate Services logs"],
            "lab/fixtures/ad_observations.json",
        ),
    }
    items: list[DetectionTuningItem] = []
    for technique_id, gap_count in counts.items():
        priority, intent, sources, fixture = metadata.get(
            technique_id,
            (
                "medium",
                "Create a technique-specific rule and synthetic regression case.",
                ["AD telemetry", "Endpoint telemetry"],
                "lab/fixtures/wazuh_alerts.json",
            ),
        )
        items.append(
            DetectionTuningItem(
                technique_id=technique_id,
                gap_count=gap_count,
                priority=priority,
                rule_intent=intent,
                event_sources=sources,
                regression_fixture=fixture,
            )
        )
    return sorted(items, key=lambda item: (-item.gap_count, item.technique_id))


_SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 60}


def evidence_manifest(evidence_id: str, session_factory: SessionFactory) -> EvidenceManifest:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        row = session.query(EvidenceItem).filter_by(id=evidence_id, tenant_id=tenant_id).first()
    if row is None:
        raise KeyError(f"Unknown evidence: {evidence_id}")
    payload = {
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
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return EvidenceManifest(
        evidence_id=row.id,
        canonical_payload=canonical_payload,
        manifest_sha256=row.manifest_sha256 or hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest(),
        generated_at=datetime.now(timezone.utc),
    )


def remediation_sla(session_factory: SessionFactory) -> list[RemediationSlaItem]:
    tenant_id = current_tenant_id()
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        rows = (
            session.query(RemediationItem)
            .filter_by(tenant_id=tenant_id)
            .order_by(RemediationItem.updated_at.desc())
            .all()
        )
    results: list[RemediationSlaItem] = []
    for row in rows:
        target_days = _SLA_DAYS.get(row.priority, _SLA_DAYS["medium"])
        due = date.fromisoformat(row.due_date) if row.due_date else row.created_at.date() + timedelta(days=target_days)
        if row.status in {"closed", "resolved"}:
            state = "closed"
        elif due < now.date():
            state = "overdue"
        elif (due - now.date()).days <= max(2, target_days // 5):
            state = "due_soon"
        else:
            state = "on_track"
        results.append(
            RemediationSlaItem(
                remediation_id=row.id,
                finding_title=row.finding_title,
                priority=row.priority,
                status=row.status,
                owner=row.owner,
                assigned_to=row.assigned_to,
                due_date=due.isoformat(),
                target_days=target_days,
                state=state,
            )
        )
    return results


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
                recommended_action=action,
            )
        )
    return escalations


def campaign_export(campaign_id: str, session_factory: SessionFactory) -> CampaignExport:
    tenant_id = current_tenant_id()
    with session_factory() as session:
        campaign_row = (
            tenant_query(session.query(Campaign), Campaign, tenant_id)
            .filter(Campaign.id == campaign_id)
            .first()
        )
    if campaign_row is None:
        raise KeyError(f"Unknown campaign: {campaign_id}")
    campaign = _campaign_response(campaign_row)
    timeline = campaign_timeline(campaign_id, session_factory)
    evidence = list_evidence(session_factory, campaign_id)
    remediations = list_remediations(session_factory, campaign_id)
    trend = risk_trend(session_factory)
    tuning = detection_tuning_queue(session_factory)
    custody_history = list_custody_history(campaign_id, session_factory)
    governance_history = list_governance_history(campaign_id, session_factory)
    from app.services.governance import list_risk_acceptances  # noqa: PLC0415

    risk_acceptances = [
        item for item in list_risk_acceptances(session_factory) if item.campaign_id == campaign_id
    ]
    remediation_ids = {row.remediation_id for row in remediations}
    sla_escalations = [
        item for item in remediation_escalations(session_factory) if item.remediation_id in remediation_ids
    ]
    actor = current_actor()
    package = {
        "schema_version": "case-export.v3",
        "tenant_id": tenant_id,
        "actor": actor,
        "campaign": campaign.model_dump(mode="json"),
        "timeline": [item.model_dump(mode="json") for item in timeline],
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "remediations": [item.model_dump(mode="json") for item in remediations],
        "custody_history": [item.model_dump(mode="json") for item in custody_history],
        "governance_history": [item.model_dump(mode="json") for item in governance_history],
        "risk_acceptances": [item.model_dump(mode="json") for item in risk_acceptances],
        "sla_escalations": [item.model_dump(mode="json") for item in sla_escalations],
        "trend": [item.model_dump(mode="json") for item in trend],
        "detection_tuning": [item.model_dump(mode="json") for item in tuning],
    }
    canonical = json.dumps(package, sort_keys=True, separators=(",", ":"))
    return CampaignExport(
        schema_version="case-export.v3",
        tenant_id=tenant_id,
        actor=actor,
        campaign=campaign,
        timeline=timeline,
        evidence=evidence,
        remediations=remediations,
        custody_history=custody_history,
        governance_history=governance_history,
        risk_acceptances=risk_acceptances,
        sla_escalations=sla_escalations,
        trend=trend,
        detection_tuning=tuning,
        manifest_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        generated_at=datetime.now(timezone.utc),
    )
