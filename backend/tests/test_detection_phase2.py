from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import Settings
from app.main import create_app
from app.models.telemetry import TelemetryEvent
from app.schemas.contracts import AttackPathEvidence, NormalizedRegressionFixture
from app.services.detection_framework import DetectionRuleCatalog
from app.services.siem_ingestion import normalize_wazuh_document
from fastapi.testclient import TestClient


def _event(
    event_id: str,
    *,
    tenant_id: str = "tenant-a",
    description: str = "T1558.003 Kerberoasting signal",
    source: str = "wazuh",
    event_code: str = "4769",
    user: str = "analyst01",
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        source=source,
        observed_at=datetime(2026, 8, 13, 1, tzinfo=timezone.utc),
        severity="high",
        rule_id="100001",
        rule_description=description,
        asset_id="wazuh-agent:007",
        technique_ids=["T1558.003"],
        summary="Synthetic normalized telemetry",
        safe_fields={"event_id": event_code, "srcuser": user},
        raw_sha256="a" * 64,
    )


def _path(*, tenant_id: str = "tenant-a") -> AttackPathEvidence:
    return AttackPathEvidence(
        tenant_id=tenant_id,
        path_id="path-123456789abc",
        risk_score=82.5,
        risk_level="critical",
        technique_ids=["T1558.003"],
        asset_ids=["wazuh-agent:007"],
        summary="Synthetic modeled path evidence",
        captured_at=datetime(2026, 8, 13, 1, tzinfo=timezone.utc),
    )


def test_normalize_wazuh_document_preserves_only_allowlisted_detection_scalars() -> None:
    event = normalize_wazuh_document(
        {
            "_id": "normalized-001",
            "_source": {
                "timestamp": "2026-08-13T01:00:00Z",
                "rule": {"description": "T1558.003 service-ticket signal", "level": 10},
                "data": {
                    "event_id": "4769",
                    "srcuser": "analyst01",
                    "preauth_required": False,
                    "password": "must-not-leak",
                    "command": "must-not-leak",
                },
            },
        },
        "tenant-a",
    )
    assert event.safe_fields == {"event_id": "4769", "srcuser": "analyst01", "preauth_required": False}
    assert "password" not in event.model_dump_json()
    assert "command" not in event.model_dump_json()


def test_normalized_evaluation_returns_provenance_and_path_evidence() -> None:
    catalog = DetectionRuleCatalog()
    result = catalog.evaluate_normalized_telemetry(
        [_event("telemetry-001")],
        ["ad.kerberoasting.service-ticket"],
        tenant_id="tenant-a",
        actor="analyst01",
        attack_paths=[_path()],
    )
    assert result.tenant_id == "tenant-a"
    assert result.actor == "analyst01"
    assert result.rule_provenance[0].source == "builtin"
    assert len(result.rule_provenance[0].content_sha256) == 64
    assert result.matches[0].rule_version == 1
    assert result.matches[0].provenance_sha256 == result.rule_provenance[0].content_sha256
    assert result.matches[0].path_evidence_ids == ["path-123456789abc"]


def test_coverage_scores_are_deterministic_and_path_aware() -> None:
    catalog = DetectionRuleCatalog()
    events = [_event("telemetry-002")]
    first = catalog.coverage_report(
        events,
        ["ad.kerberoasting.service-ticket", "adcs.template.client-auth"],
        tenant_id="tenant-a",
        actor="analyst01",
        attack_paths=[_path()],
        dry_run=True,
    )
    second = catalog.coverage_report(
        events,
        ["ad.kerberoasting.service-ticket", "adcs.template.client-auth"],
        tenant_id="tenant-a",
        actor="analyst01",
        attack_paths=[_path()],
        dry_run=True,
    )
    assert first.coverage_percent == second.coverage_percent == 50.0
    assert first.path_coverage_percent == second.path_coverage_percent == 100.0
    assert first.observations == second.observations
    assert first.path_evidence_ids == ["path-123456789abc"]
    assert "analyst01" not in first.observations[0].rationale


def test_normalized_regression_report_is_safe_and_explainable() -> None:
    catalog = DetectionRuleCatalog()
    report = catalog.run_normalized_regressions(
        [
            NormalizedRegressionFixture(
                fixture_id="kerberoasting-positive",
                title="Synthetic positive",
                rule_id="ad.kerberoasting.service-ticket",
                expected_match=True,
                telemetry=[_event("telemetry-positive")],
                attack_paths=[_path()],
            ),
            NormalizedRegressionFixture(
                fixture_id="kerberoasting-negative",
                title="Synthetic benign event",
                rule_id="ad.kerberoasting.service-ticket",
                expected_match=False,
                telemetry=[_event("telemetry-negative", description="Normal service ticket")],
            ),
        ],
        [],
        tenant_id="tenant-a",
        actor="analyst01",
        dry_run=True,
    )
    assert report.status == "passed"
    assert report.true_positive_rate == 100.0
    assert report.false_positive_rate == 0.0
    positive_case = next(case for case in report.cases if case.fixture_id == "kerberoasting-positive")
    assert positive_case.path_evidence_ids == ["path-123456789abc"]
    serialized = report.model_dump_json()
    assert "safe_fields" not in serialized
    assert "analyst01" in serialized
    assert "password" not in serialized


def test_coverage_api_derives_actor_and_rejects_cross_tenant_evidence(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'phase2.db'}",
        audit_log_path=str(tmp_path / "audit.jsonl"),
        auth_bootstrap_token="phase-two-test-bootstrap-token",
    )
    with TestClient(create_app(settings)) as client:
        assert client.post("/api/v1/detections/coverage", json={"telemetry": []}).status_code == 401
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": settings.auth_bootstrap_token,
                "tenant_slug": "phase-two",
                "tenant_name": "Phase Two Test Tenant",
                "username": "phase-two-admin",
                "password": "phase-two-admin-password",
            },
        )
        assert bootstrap.status_code == 201
        headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
        tenant_id = bootstrap.json()["tenant_id"]
        payload = {
            "rule_ids": ["ad.kerberoasting.service-ticket"],
            "telemetry": [_event("api-telemetry", tenant_id=tenant_id).model_dump(mode="json")],
            "attack_paths": [_path(tenant_id="other-tenant").model_dump(mode="json")],
        }
        rejected = client.post("/api/v1/detections/coverage", json=payload, headers=headers)
        assert rejected.status_code == 403

        payload["attack_paths"] = []
        payload["telemetry"] = [_event("api-cross-tenant", tenant_id="other-tenant").model_dump(mode="json")]
        rejected_telemetry = client.post("/api/v1/detections/coverage", json=payload, headers=headers)
        assert rejected_telemetry.status_code == 403

        payload["telemetry"] = [_event("api-telemetry", tenant_id=tenant_id).model_dump(mode="json")]
        payload["attack_paths"] = [_path(tenant_id=tenant_id).model_dump(mode="json")]
        response = client.post("/api/v1/detections/coverage", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["actor"] == "phase-two-admin"
        assert response.json()["tenant_id"] == tenant_id
        assert response.json()["dry_run"] is True
        assert response.json()["path_evidence_ids"] == ["path-123456789abc"]

        integrity = client.get("/api/v1/integrity/audit", headers=headers)
        assert integrity.status_code == 200
        assert integrity.json()["valid"] is True


def test_normalized_regression_api_reports_only_bounded_evidence(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'regressions.db'}",
        audit_log_path=str(tmp_path / "audit.jsonl"),
        auth_bootstrap_token="normalized-regression-test-token",
    )
    with TestClient(create_app(settings)) as client:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": settings.auth_bootstrap_token,
                "tenant_slug": "regression",
                "tenant_name": "Regression Test Tenant",
                "username": "regression-admin",
                "password": "regression-admin-password",
            },
        )
        assert bootstrap.status_code == 201
        headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
        tenant_id = bootstrap.json()["tenant_id"]
        fixture = NormalizedRegressionFixture(
            fixture_id="api-positive",
            title="Synthetic API positive",
            rule_id="ad.kerberoasting.service-ticket",
            expected_match=True,
            telemetry=[_event("api-regression-event", tenant_id=tenant_id)],
            attack_paths=[_path(tenant_id=tenant_id)],
        )
        response = client.post(
            "/api/v1/detections/regressions/normalized",
            json={"fixtures": [fixture.model_dump(mode="json")]},
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "passed"
        assert body["actor"] == "regression-admin"
        assert body["cases"][0]["telemetry_event_ids"] == ["api-regression-event"]
        assert "safe_fields" not in response.text
        assert "password" not in response.text


def test_attack_path_linkage_requires_compatible_asset_context() -> None:
    catalog = DetectionRuleCatalog()
    unrelated_path = _path().model_copy(
        update={"path_id": "path-abcdefabcdef", "asset_ids": ["unrelated-asset"]}
    )
    result = catalog.evaluate_normalized_telemetry(
        [_event("telemetry-asset-match")],
        ["ad.kerberoasting.service-ticket"],
        tenant_id="tenant-a",
        actor="analyst01",
        attack_paths=[unrelated_path],
    )
    assert result.matches[0].path_evidence_ids == []
