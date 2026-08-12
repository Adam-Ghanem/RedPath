from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from app.db.models import AssessmentRun
from app.schemas.contracts import (
    AssessmentRunSummary,
    ScenarioRunRequest,
    ScenarioRunResponse,
)
from app.services.ad_detection import detect_ad_findings
from app.services.correlation import correlate_findings
from app.services.purple import build_detection_gap_report
from app.services.scenarios import get_scenario

SessionFactory = Callable[[], object]


def execute_scenario(request: ScenarioRunRequest, session_factory: SessionFactory) -> ScenarioRunResponse:
    scenario = get_scenario(request.scenario_id)
    findings = detect_ad_findings(request.observations)
    coverage = build_detection_gap_report(scenario.technique_ids, request.alerts)
    correlated = correlate_findings(findings)
    risk_score = max((item.risk_score for item in correlated), default=0.0)
    recommendations = [item.recommendation for item in coverage.observations if item.recommendation]
    run_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    summary = (
        f"{scenario.name} completed in {'dry-run' if request.dry_run else 'evidence-import'} mode: "
        f"{len(findings)} findings, {coverage.coverage_percent:.2f}% detection coverage, "
        f"{len(coverage.gaps)} detection gaps."
    )
    with session_factory() as session:
        session.add(
            AssessmentRun(
                id=run_id,
                scenario_id=scenario.scenario_id,
                status="completed",
                dry_run=request.dry_run,
                risk_score=risk_score,
                coverage_percent=coverage.coverage_percent,
                finding_count=len(findings),
                gap_count=len(coverage.gaps),
                findings=[finding.model_dump(mode="json") for finding in findings],
                gaps=coverage.gaps,
                summary=summary,
                created_at=created_at,
            )
        )
        session.commit()
    return ScenarioRunResponse(
        run_id=run_id,
        scenario_id=scenario.scenario_id,
        status="completed",
        dry_run=request.dry_run,
        risk_score=risk_score,
        coverage_percent=coverage.coverage_percent,
        finding_count=len(findings),
        gap_count=len(coverage.gaps),
        summary=summary,
        created_at=created_at,
        findings=findings,
        gaps=coverage.gaps,
        recommendations=recommendations,
    )


def list_run_summaries(session_factory: SessionFactory, limit: int = 20) -> list[AssessmentRunSummary]:
    with session_factory() as session:
        rows = session.query(AssessmentRun).order_by(AssessmentRun.created_at.desc()).limit(limit).all()
    return [
        AssessmentRunSummary(
            run_id=row.id,
            scenario_id=row.scenario_id,
            status=row.status,
            dry_run=row.dry_run,
            risk_score=row.risk_score,
            coverage_percent=row.coverage_percent,
            finding_count=row.finding_count,
            gap_count=row.gap_count,
            summary=row.summary,
            created_at=row.created_at,
        )
        for row in rows
    ]
