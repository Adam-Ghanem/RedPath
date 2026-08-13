from datetime import datetime, timezone
from uuid import uuid4

import pytest
from app.core.config import Settings
from app.main import create_app
from app.schemas.contracts import DetectionCondition, DetectionRule, WazuhAlert
from app.services.detection_framework import DetectionRuleCatalog, builtin_regression_fixtures
from fastapi.testclient import TestClient

settings = Settings(
    database_url=f"sqlite:////tmp/redpath-detection-{uuid4().hex}.db",
    audit_log_path=f"/tmp/redpath-detection-{uuid4().hex}.jsonl",
    auth_bootstrap_token="detection-test-bootstrap-token",
)
client = TestClient(create_app(settings))
bootstrap = client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "detection",
        "tenant_name": "Detection Test Tenant",
        "username": "detection-admin",
        "password": "detection-admin-password",
    },
)
assert bootstrap.status_code == 201
AUTH_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def _alert(alert_id: str, timestamp: str, description: str, **data: object) -> WazuhAlert:
    return WazuhAlert(id=alert_id, timestamp=timestamp, rule={"description": description}, data=data)


def test_builtin_rule_matches_synthetic_kerberoasting_event() -> None:
    catalog = DetectionRuleCatalog()
    result = catalog.evaluate(
        [
            _alert(
                "alert-1",
                "2026-08-12T02:00:00Z",
                "T1558.003 Kerberoasting signal",
                event_id="4769",
                srcuser="analyst01",
            )
        ],
        ["ad.kerberoasting.service-ticket"],
    )

    assert result.event_count == 1
    assert result.rule_count == 1
    assert len(result.matches) == 1
    assert result.matches[0].technique_ids == ["T1558.003"]
    assert result.matches[0].alert_ids == ["alert-1"]
    assert result.matches[0].first_seen == datetime(2026, 8, 12, 2, 0, tzinfo=timezone.utc)


def test_correlation_requires_conditions_in_same_group_and_window() -> None:
    catalog = DetectionRuleCatalog()
    catalog.add_rule(
        DetectionRule(
            rule_id="test.sequence.rule",
            title="Synthetic two-event sequence",
            description="A test-only rule requiring two related synthetic events.",
            technique_ids=["T0000.001"],
            severity="medium",
            event_sources=["wazuh"],
            conditions=[
                DetectionCondition(path="data.stage", operator="equals", value="start"),
                DetectionCondition(path="data.stage", operator="equals", value="finish"),
            ],
            window_seconds=60,
            group_by=["data.user"],
        )
    )

    within_window = catalog.evaluate(
        [
            _alert("start-1", "2026-08-12T02:00:00Z", "start", stage="start", user="alice"),
            _alert("finish-1", "2026-08-12T02:00:30Z", "finish", stage="finish", user="alice"),
        ],
        ["test.sequence.rule"],
    )
    outside_window = catalog.evaluate(
        [
            _alert("start-2", "2026-08-12T02:00:00Z", "start", stage="start", user="alice"),
            _alert("finish-2", "2026-08-12T02:02:00Z", "finish", stage="finish", user="alice"),
        ],
        ["test.sequence.rule"],
    )

    assert len(within_window.matches) == 1
    assert within_window.matches[0].matched_condition_count == 2
    assert within_window.matches[0].group_key == "alice"
    assert outside_window.matches == []


def test_builtin_regression_suite_reports_fidelity_metrics() -> None:
    report = DetectionRuleCatalog().run_regressions(builtin_regression_fixtures(), [])

    assert report.status == "passed"
    assert report.total_cases == 4
    assert report.passed_cases == 4
    assert report.failed_cases == 0
    assert report.true_positive_rate == 100.0
    assert report.false_positive_rate == 0.0


def test_api_exposes_rules_evaluation_and_regression_endpoints() -> None:
    rules = client.get("/api/v1/detections/rules", headers=AUTH_HEADERS)
    assert rules.status_code == 200
    assert {item["rule_id"] for item in rules.json()} >= {
        "ad.kerberoasting.service-ticket",
        "ad.asrep.preauth-disabled",
        "adcs.template.client-auth",
    }

    evaluation = client.post(
        "/api/v1/detections/evaluate",
        json={
            "rule_ids": ["ad.kerberoasting.service-ticket"],
            "events": [
                {
                    "id": "api-alert-1",
                    "timestamp": "2026-08-12T02:00:00Z",
                    "rule": {"description": "T1558.003 Kerberoasting signal"},
                    "data": {"event_id": "4769", "srcuser": "analyst01"},
                }
            ],
        },
        headers=AUTH_HEADERS,
    )
    assert evaluation.status_code == 200
    assert evaluation.json()["matches"][0]["rule_id"] == "ad.kerberoasting.service-ticket"

    regression = client.post("/api/v1/detections/regressions/run", json={}, headers=AUTH_HEADERS)
    assert regression.status_code == 200
    assert regression.json()["status"] == "passed"
    assert regression.json()["false_positive_rate"] == 0.0


def test_rule_registration_rejects_unapproved_production_rule() -> None:
    response = client.post(
        "/api/v1/detections/rules",
        json={
            "rule_id": "test.unapproved.production",
            "title": "Unapproved production rule",
            "description": "This rule must not be registered as production without approval.",
            "technique_ids": ["T0000.002"],
            "severity": "high",
            "event_sources": ["wazuh"],
            "conditions": [{"path": "data.kind", "operator": "equals", "value": "synthetic"}],
            "deployment_status": "production",
            "requires_approval": False,
        },
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 422
    assert "must require approval" in response.json()["detail"]


def test_unknown_rule_is_not_silently_ignored() -> None:
    with pytest.raises(KeyError, match="unknown"):
        DetectionRuleCatalog().evaluate([], ["unknown.rule"])
