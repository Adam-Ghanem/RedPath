from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from app.db.models import AssessmentRun, Campaign, CampaignRunLink, EvidenceItem, RemediationItem, utcnow
from app.schemas.contracts import (
    CampaignCreate,
    CampaignExport,
    CampaignResponse,
    CampaignTimelineEvent,
    DetectionTuningItem,
    EvidenceCreate,
    EvidenceManifest,
    EvidenceResponse,
    RemediationCreate,
    RemediationResponse,
    RemediationSlaItem,
    TrendPoint,
)

SessionFactory = Callable[[], object]


def _campaign_response(row: Campaign) -> CampaignResponse:
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


def create_campaign(request: CampaignCreate, session_factory: SessionFactory) -> CampaignResponse:
    now = utcnow()
    row = Campaign(
        id=str(uuid4()),
        name=request.name,
        objective=request.objective,
        owner=request.owner,
        scope_snapshot=request.scope_snapshot,
        status="active",
        created_at=now,
        updated_at=now,
    )
    with session_factory() as session:
        session.add(row)
        session.commit()
        session.refresh(row)
    return _campaign_response(row)


def list_campaigns(session_factory: SessionFactory) -> list[CampaignResponse]:
    with session_factory() as session:
        rows = session.query(Campaign).order_by(Campaign.updated_at.desc()).all()
    return [_campaign_response(row) for row in rows]


def link_run(campaign_id: str, run_id: str, session_factory: SessionFactory) -> None:
    with session_factory() as session:
        if session.get(Campaign, campaign_id) is None:
            raise KeyError(f"Unknown campaign: {campaign_id}")
        if session.get(AssessmentRun, run_id) is None:
            raise KeyError(f"Unknown assessment run: {run_id}")
        existing = session.query(CampaignRunLink).filter_by(campaign_id=campaign_id, run_id=run_id).first()
        if existing is None:
            session.add(CampaignRunLink(campaign_id=campaign_id, run_id=run_id))
        session.commit()


def create_evidence(request: EvidenceCreate, session_factory: SessionFactory) -> EvidenceResponse:
    row = EvidenceItem(
        id=str(uuid4()),
        campaign_id=request.campaign_id,
        run_id=request.run_id,
        evidence_type=request.evidence_type,
        source=request.source,
        title=request.title,
        sha256=request.sha256,
        technique_id=request.technique_id,
        notes=request.notes,
        review_status="unreviewed",
    )
    with session_factory() as session:
        if request.campaign_id and session.get(Campaign, request.campaign_id) is None:
            raise KeyError(f"Unknown campaign: {request.campaign_id}")
        if request.run_id and session.get(AssessmentRun, request.run_id) is None:
            raise KeyError(f"Unknown assessment run: {request.run_id}")
        session.add(row)
        session.commit()
        session.refresh(row)
    return EvidenceResponse(
        **request.model_dump(),
        evidence_id=row.id,
        review_status=row.review_status,
        created_at=row.created_at,
    )


def list_evidence(session_factory: SessionFactory, campaign_id: str | None = None) -> list[EvidenceResponse]:
    with session_factory() as session:
        query = session.query(EvidenceItem).order_by(EvidenceItem.created_at.desc())
        rows = query.filter_by(campaign_id=campaign_id).all() if campaign_id else query.all()
    return [
        EvidenceResponse(
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
            created_at=row.created_at,
        )
        for row in rows
    ]


def create_remediation(request: RemediationCreate, session_factory: SessionFactory) -> RemediationResponse:
    now = utcnow()
    row = RemediationItem(
        id=str(uuid4()),
        campaign_id=request.campaign_id,
        finding_title=request.finding_title,
        technique_id=request.technique_id,
        recommendation=request.recommendation,
        owner=request.owner,
        priority=request.priority,
        status="open",
        due_date=request.due_date,
        created_at=now,
        updated_at=now,
    )
    with session_factory() as session:
        if request.campaign_id and session.get(Campaign, request.campaign_id) is None:
            raise KeyError(f"Unknown campaign: {request.campaign_id}")
        session.add(row)
        session.commit()
        session.refresh(row)
    return RemediationResponse(
        **request.model_dump(),
        remediation_id=row.id,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def list_remediations(session_factory: SessionFactory, campaign_id: str | None = None) -> list[RemediationResponse]:
    with session_factory() as session:
        query = session.query(RemediationItem).order_by(RemediationItem.updated_at.desc())
        rows = query.filter_by(campaign_id=campaign_id).all() if campaign_id else query.all()
    return [
        RemediationResponse(
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
        for row in rows
    ]


def campaign_timeline(campaign_id: str, session_factory: SessionFactory) -> list[CampaignTimelineEvent]:
    with session_factory() as session:
        if session.get(Campaign, campaign_id) is None:
            raise KeyError(f"Unknown campaign: {campaign_id}")
        links = session.query(CampaignRunLink).filter_by(campaign_id=campaign_id).all()
        evidence = session.query(EvidenceItem).filter_by(campaign_id=campaign_id).all()
        remediations = session.query(RemediationItem).filter_by(campaign_id=campaign_id).all()
        run_ids = [link.run_id for link in links]
        run_rows = session.query(AssessmentRun).filter(AssessmentRun.id.in_(run_ids)).all() if run_ids else []
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
    with session_factory() as session:
        rows = session.query(AssessmentRun).order_by(AssessmentRun.created_at.asc()).all()
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
    with session_factory() as session:
        rows = session.query(AssessmentRun).all()
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
    with session_factory() as session:
        row = session.get(EvidenceItem, evidence_id)
    if row is None:
        raise KeyError(f"Unknown evidence: {evidence_id}")
    payload = {
        "evidence_id": row.id,
        "campaign_id": row.campaign_id,
        "run_id": row.run_id,
        "evidence_type": row.evidence_type,
        "source": row.source,
        "title": row.title,
        "sha256": row.sha256,
        "technique_id": row.technique_id,
        "review_status": row.review_status,
        "notes": row.notes,
    }
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return EvidenceManifest(
        evidence_id=row.id,
        canonical_payload=canonical_payload,
        manifest_sha256=hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest(),
        generated_at=datetime.now(timezone.utc),
    )


def remediation_sla(session_factory: SessionFactory) -> list[RemediationSlaItem]:
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        rows = session.query(RemediationItem).order_by(RemediationItem.updated_at.desc()).all()
    results: list[RemediationSlaItem] = []
    for row in rows:
        target_days = _SLA_DAYS.get(row.priority, _SLA_DAYS["medium"])
        due = (
            date.fromisoformat(row.due_date)
            if row.due_date
            else row.created_at.date() + timedelta(days=target_days)
        )
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
                due_date=due.isoformat(),
                target_days=target_days,
                state=state,
            )
        )
    return results


def campaign_export(campaign_id: str, session_factory: SessionFactory) -> CampaignExport:
    with session_factory() as session:
        campaign_row = session.get(Campaign, campaign_id)
    if campaign_row is None:
        raise KeyError(f"Unknown campaign: {campaign_id}")
    campaign = _campaign_response(campaign_row)
    timeline = campaign_timeline(campaign_id, session_factory)
    evidence = list_evidence(session_factory, campaign_id)
    remediations = list_remediations(session_factory, campaign_id)
    trend = risk_trend(session_factory)
    tuning = detection_tuning_queue(session_factory)
    package = {
        "campaign": campaign.model_dump(mode="json"),
        "timeline": [item.model_dump(mode="json") for item in timeline],
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "remediations": [item.model_dump(mode="json") for item in remediations],
        "trend": [item.model_dump(mode="json") for item in trend],
        "detection_tuning": [item.model_dump(mode="json") for item in tuning],
    }
    canonical = json.dumps(package, sort_keys=True, separators=(",", ":"))
    return CampaignExport(
        campaign=campaign,
        timeline=timeline,
        evidence=evidence,
        remediations=remediations,
        trend=trend,
        detection_tuning=tuning,
        manifest_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        generated_at=datetime.now(timezone.utc),
    )
