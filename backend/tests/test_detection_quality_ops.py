from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from app.core.config import Settings
from app.main import create_app
from app.schemas.contracts import (
    CoverageDriftRequest,
    DetectionQualitySnapshot,
    DetectionRule,
    FalsePositiveReviewCreate,
    RegressionTrendPoint,
    RegressionTrendRequest,
    TuningProposalCreate,
    TuningProposalReviewRequest,
)
from app.services.detection_framework import DetectionRuleCatalog
from app.services.detection_quality_ops import DetectionQualityError, DetectionQualityNotFound, DetectionQualityService
from fastapi.testclient import TestClient
from pydantic import ValidationError


def _service() -> DetectionQualityService:
    return DetectionQualityService(
        DetectionRuleCatalog(),
        now_fn=lambda: datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
    )


def _proposal(proposal_type: str = "reduce_false_positives") -> TuningProposalCreate:
    return TuningProposalCreate(
        rule_id="ad.kerberoasting.service-ticket",
        rule_version=1,
        proposal_type=proposal_type,
        summary="Review a repeated benign service-ticket signal",
        rationale="The synthetic benign fixture demonstrates a candidate tuning review without changing the rule.",
        evidence_fixture_ids=["ad.kerberoasting.negative"],
        target_false_positive_rate=1.0,
    )


def _snapshot(snapshot_id: str, tenant_id: str, coverage: float, fpr: float) -> DetectionQualitySnapshot:
    return DetectionQualitySnapshot(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        captured_at=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
        rule_count=3,
        coverage_percent=coverage,
        path_coverage_percent=80.0,
        true_positive_rate=95.0,
        false_positive_rate=fpr,
    )


def test_tuning_proposal_requires_separate_reviewer_and_is_tenant_scoped() -> None:
    service = _service()
    proposal = service.create_tuning_proposal(_proposal(), tenant_id="tenant-a", actor="analyst-a")

    with pytest.raises(DetectionQualityError, match="cannot review"):
        service.review_tuning_proposal(
            proposal.proposal_id,
            TuningProposalReviewRequest(decision="approve", review_note="Independent review is required."),
            tenant_id="tenant-a",
            reviewer="analyst-a",
        )
    with pytest.raises(DetectionQualityNotFound):
        service.review_tuning_proposal(
            proposal.proposal_id,
            TuningProposalReviewRequest(decision="approve", review_note="Wrong tenant must not see this proposal."),
            tenant_id="tenant-b",
            reviewer="reviewer-b",
        )

    reviewed = service.review_tuning_proposal(
        proposal.proposal_id,
        TuningProposalReviewRequest(decision="approve", review_note="Evidence and rationale reviewed independently."),
        tenant_id="tenant-a",
        reviewer="reviewer-a",
    )
    assert reviewed.status == "approved"
    assert reviewed.reviewed_by == "reviewer-a"


def test_false_positive_review_is_bounded_and_rule_versioned() -> None:
    review = _service().record_false_positive_review(
        FalsePositiveReviewCreate(
            alert_id="alert-benign-1",
            rule_id="ad.kerberoasting.service-ticket",
            rule_version=1,
            classification="false_positive",
            reason_code="expected_automation",
            analyst_note="Expected scheduled service activity; retain for fixture review.",
            evidence_fixture_id="ad.kerberoasting.negative",
        ),
        tenant_id="tenant-a",
        reviewer="reviewer-a",
    )

    assert review.tenant_id == "tenant-a"
    assert review.rule_version == 1
    assert review.classification == "false_positive"


def test_coverage_drift_is_signed_deterministic_and_tenant_safe() -> None:
    report = _service().compare_coverage_drift(
        CoverageDriftRequest(
            baseline=_snapshot("baseline-1", "tenant-a", 100.0, 0.0),
            current=_snapshot("current-1", "tenant-a", 92.0, 8.0),
        ),
        tenant_id="tenant-a",
    )

    assert report.coverage_delta_percent == -8.0
    assert report.false_positive_delta_percent == 8.0
    assert report.drift_detected is True
    assert len(report.drift_reasons) == 2
    with pytest.raises(DetectionQualityError, match="authenticated tenant"):
        _service().compare_coverage_drift(
            CoverageDriftRequest(
                baseline=_snapshot("baseline-1", "tenant-a", 100.0, 0.0),
                current=_snapshot("current-1", "tenant-b", 92.0, 8.0),
            ),
            tenant_id="tenant-a",
        )


def test_regression_trend_sorts_points_and_reports_degradation() -> None:
    request = RegressionTrendRequest(
        tenant_id="tenant-a",
        points=[
            RegressionTrendPoint(
                run_id="run-2",
                captured_at=datetime(2026, 8, 14, 12, 2, tzinfo=timezone.utc),
                total_cases=4,
                passed_cases=3,
                true_positive_rate=90.0,
                false_positive_rate=5.0,
                coverage_percent=90.0,
            ),
            RegressionTrendPoint(
                run_id="run-1",
                captured_at=datetime(2026, 8, 14, 12, 1, tzinfo=timezone.utc),
                total_cases=4,
                passed_cases=4,
                true_positive_rate=100.0,
                false_positive_rate=0.0,
                coverage_percent=100.0,
            ),
        ],
    )

    report = _service().regression_trend(request, tenant_id="tenant-a")

    assert [point.run_id for point in report.points] == ["run-1", "run-2"]
    assert report.direction == "degrading"
    assert report.coverage_delta_percent == -10.0


def test_deprecation_windows_are_safe_and_deterministic() -> None:
    service = _service()
    service.catalog.add_rule(
        DetectionRule(
            rule_id="test.scheduled.rule",
            title="Synthetic scheduled deprecation rule",
            description="This synthetic rule exercises a bounded deprecation window.",
            technique_ids=["T1558.003"],
            severity="low",
            event_sources=["wazuh"],
            conditions=[{"path": "data.event_id", "operator": "equals", "value": "4769"}],
            owner="test-owner",
            telemetry_requirements=["wazuh.security"],
            deprecation_status="scheduled",
            deprecation_sunset_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc),
            replacement_rule_id="ad.kerberoasting.service-ticket",
            deprecation_reason="Synthetic replacement review window.",
        )
    )

    report = service.deprecation_report(now=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc))
    scheduled = next(window for window in report.windows if window.rule_id == "test.scheduled.rule")

    assert len(report.windows) == 4
    assert scheduled.status == "scheduled"
    assert scheduled.days_remaining == 6
    assert scheduled.replacement_rule_id == "ad.kerberoasting.service-ticket"


def test_fixture_quality_inputs_reject_raw_payload_fields() -> None:
    with pytest.raises(ValidationError):
        DetectionQualitySnapshot.model_validate(
            {
                "snapshot_id": "snapshot-1",
                "tenant_id": "tenant-a",
                "captured_at": "2026-08-14T12:00:00Z",
                "rule_count": 3,
                "coverage_percent": 100,
                "path_coverage_percent": 100,
                "true_positive_rate": 100,
                "false_positive_rate": 0,
                "raw_payload": {"untrusted": "data"},
            }
        )


def test_trend_performance_stays_bounded_for_max_fixture_history() -> None:
    service = _service()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    request = RegressionTrendRequest(
        tenant_id="tenant-a",
        points=[
            RegressionTrendPoint(
                run_id=f"run-{index:03d}",
                captured_at=start + timedelta(days=index),
                total_cases=4,
                passed_cases=4,
                true_positive_rate=100.0,
                false_positive_rate=0.0,
                coverage_percent=100.0,
            )
            for index in range(90)
        ],
    )

    started = time.perf_counter()
    report = service.regression_trend(request, tenant_id="tenant-a")
    elapsed = time.perf_counter() - started

    assert len(report.points) == 90
    assert elapsed < 1.0


def test_quality_api_requires_auth_and_derives_tenant_and_actor(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / f'quality-{uuid4().hex}.db'}",
        audit_log_path=str(tmp_path / f'quality-{uuid4().hex}.jsonl'),
        auth_bootstrap_token="quality-bootstrap-token",
    )
    with TestClient(create_app(settings)) as client:
        unauthenticated = client.get("/api/v1/detections/quality/deprecation-windows")
        assert unauthenticated.status_code == 401
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": settings.auth_bootstrap_token,
                "tenant_slug": "quality",
                "tenant_name": "Quality Test Tenant",
                "username": "quality-admin",
                "password": "quality-admin-password",
            },
        )
        assert bootstrap.status_code == 201
        headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
        proposal = client.post(
            "/api/v1/detections/quality/tuning-proposals",
            json=_proposal().model_dump(mode="json"),
            headers=headers,
        )
        assert proposal.status_code == 200
        assert proposal.json()["tenant_id"] == bootstrap.json()["tenant_id"]
        assert proposal.json()["created_by"] == "quality-admin"
        review = client.post(
            f"/api/v1/detections/quality/tuning-proposals/{proposal.json()['proposal_id']}/review",
            json={"decision": "approve", "review_note": "Self-review should fail closed for separation of duties."},
            headers=headers,
        )
        assert review.status_code == 422
        drift = client.post(
            "/api/v1/detections/quality/coverage-drift",
            json={
                "baseline": _snapshot(
                    "baseline-api", bootstrap.json()["tenant_id"], 100.0, 0.0
                ).model_dump(mode="json"),
                "current": _snapshot("current-api", "other-tenant", 92.0, 8.0).model_dump(mode="json"),
            },
            headers=headers,
        )
        assert drift.status_code == 422
        audit_text = Path(settings.audit_log_path).read_text()
        assert "detection.quality_tuning_proposed" in audit_text
        assert "Self-review should fail closed" not in audit_text


def test_quality_operation_timestamps_require_timezone() -> None:
    payload = _proposal("deprecate_rule").model_dump(mode="json")
    payload["proposed_sunset_at"] = "2026-08-20T12:00:00"
    with pytest.raises(ValidationError):
        TuningProposalCreate.model_validate(payload)
