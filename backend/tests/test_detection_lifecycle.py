from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.main import create_app
from app.schemas.contracts import (
    DetectionPackManifest,
    DetectionRule,
    NormalizedRegressionFixture,
)
from app.services.detection_framework import DetectionRuleCatalog
from app.services.detection_lifecycle import DetectionLifecycleService
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]


def _pack() -> DetectionPackManifest:
    return DetectionPackManifest.model_validate(json.loads((ROOT / "detections/pack.json").read_text()))


def _fixtures(tenant_id: str = "ci-tenant") -> list[NormalizedRegressionFixture]:
    raw = json.loads((ROOT / "detections/fixtures/core.json").read_text())
    for fixture in raw:
        for event in fixture["telemetry"]:
            event["tenant_id"] = tenant_id
        for path in fixture.get("attack_paths", []):
            path["tenant_id"] = tenant_id
    return [NormalizedRegressionFixture.model_validate(item) for item in raw]


def test_catalog_rules_are_governed_and_mitre_mappings_are_supported() -> None:
    service = DetectionLifecycleService(DetectionRuleCatalog())
    results, errors, warnings = service.validate_pack(_pack())

    assert errors == []
    assert warnings == []
    assert len(results) == 3
    assert all(result.valid and result.mitre_valid and result.safe_logic for result in results)
    assert all(result.approval_valid for result in results)


def test_unknown_mitre_and_unsafe_condition_fail_closed() -> None:
    service = DetectionLifecycleService(DetectionRuleCatalog())
    rule = DetectionRule(
        rule_id="test.unsafe.rule",
        title="Synthetic unsafe validation case",
        description="This synthetic rule must be rejected by the governance validator.",
        technique_ids=["T9999.999"],
        severity="high",
        event_sources=["wazuh"],
        conditions=[{"path": "data.password", "operator": "contains", "value": "x"}],
        owner="test-owner",
        telemetry_requirements=["wazuh.security"],
    )

    result = service.validate_rule(rule)

    assert result.valid is False
    assert result.mitre_valid is False
    assert result.safe_logic is False
    assert any("Unsupported MITRE".lower() in error.lower() for error in result.errors)
    assert any("unsafe" in error for error in result.errors)


def test_production_rule_requires_explicit_approval_evidence() -> None:
    service = DetectionLifecycleService(DetectionRuleCatalog())
    rule = DetectionRule(
        rule_id="test.production.rule",
        title="Synthetic production approval case",
        description="This synthetic rule demonstrates approval-state enforcement.",
        technique_ids=["T1558.003"],
        severity="high",
        event_sources=["wazuh"],
        conditions=[{"path": "data.event_id", "operator": "equals", "value": "4769"}],
        deployment_status="production",
        approval_state="pending",
        requires_approval=True,
        owner="test-owner",
        telemetry_requirements=["wazuh.security"],
    )

    result = service.validate_rule(rule)

    assert result.valid is False
    assert result.approval_valid is False
    assert any("approved state" in error for error in result.errors)


def test_lifecycle_gate_passes_with_baseline_and_explainable_output() -> None:
    report = DetectionLifecycleService(DetectionRuleCatalog()).run_gate(
        _pack(),
        _fixtures(),
        tenant_id="ci-tenant",
        actor="ci-gate",
        dry_run=True,
    )

    assert report.status == "passed"
    assert report.observed_true_positive_rate == 100.0
    assert report.observed_false_positive_rate == 0.0
    assert report.observed_rule_coverage_percent == 100.0
    assert report.dry_run is True
    assert len(report.pack_sha256) == 64
    assert report.regression_report is not None
    assert report.coverage_report is not None
    assert report.coverage_report.observations[0].rationale
    serialized = report.model_dump_json()
    assert "safe_fields" not in serialized
    assert "password" not in serialized


def test_lifecycle_gate_rejects_wrong_fixture_assignment() -> None:
    pack = _pack()
    fixtures = _fixtures()
    fixtures[0] = fixtures[0].model_copy(update={"rule_id": "ad.asrep.preauth-disabled"})

    report = DetectionLifecycleService(DetectionRuleCatalog()).run_gate(
        pack,
        fixtures,
        tenant_id="ci-tenant",
        actor="ci-gate",
        dry_run=True,
    )

    assert report.status == "blocked"
    assert any("assigned to the wrong rule" in error for error in report.errors)
    assert report.regression_report is None


def test_lifecycle_api_is_protected_and_derives_actor_and_tenant(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / f'lifecycle-{uuid4().hex}.db'}",
        audit_log_path=str(tmp_path / f'lifecycle-{uuid4().hex}.jsonl'),
        auth_bootstrap_token="lifecycle-bootstrap-token",
    )
    with TestClient(create_app(settings)) as client:
        unauthenticated = client.post(
            "/api/v1/detections/lifecycle/gate",
            json={"pack": _pack().model_dump(mode="json"), "fixtures": []},
        )
        assert unauthenticated.status_code == 401

        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": settings.auth_bootstrap_token,
                "tenant_slug": "lifecycle",
                "tenant_name": "Lifecycle Test Tenant",
                "username": "lifecycle-admin",
                "password": "lifecycle-admin-password",
            },
        )
        assert bootstrap.status_code == 201
        headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
        tenant_id = bootstrap.json()["tenant_id"]
        body = {
            "pack": _pack().model_dump(mode="json"),
            "fixtures": [fixture.model_dump(mode="json") for fixture in _fixtures(tenant_id)],
            "dry_run": True,
        }
        response = client.post("/api/v1/detections/lifecycle/gate", json=body, headers=headers)

        assert response.status_code == 200
        assert response.json()["status"] == "passed"
        assert response.json()["actor"] == "lifecycle-admin"
        assert response.json()["tenant_id"] == tenant_id
        assert response.json()["dry_run"] is True
        assert "lifecycle-admin" in response.text
        assert "safe_fields" not in response.text


def test_catalog_rejects_unapproved_production_registration() -> None:
    catalog = DetectionRuleCatalog()
    rule = DetectionRule(
        rule_id="test.production.registration",
        title="Synthetic production registration case",
        description="This synthetic production rule lacks approval evidence.",
        technique_ids=["T1558.003"],
        severity="high",
        event_sources=["wazuh"],
        conditions=[{"path": "data.event_id", "operator": "equals", "value": "4769"}],
        deployment_status="production",
        owner="test-owner",
        telemetry_requirements=["wazuh.security"],
    )

    try:
        catalog.add_rule(rule)
    except ValueError as exc:
        assert "approved state" in str(exc)
    else:
        raise AssertionError("unapproved production rule was registered")
