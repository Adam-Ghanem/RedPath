from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_health_and_scope_contracts() -> None:
    health = client.get("/api/v1/health")
    scope = client.get("/api/v1/scope")
    assert health.status_code == 200
    assert health.json()["dry_run_default"] is True
    assert "192.168.56.0/24" in scope.json()["allowed_cidrs"]


def test_recon_rejects_out_of_scope_target() -> None:
    response = client.post(
        "/api/v1/recon",
        json={"targets": ["8.8.8.8"], "profile": "safe", "dry_run": True},
    )
    assert response.status_code == 403


def test_detection_and_risk_correlation_endpoints() -> None:
    findings = client.post(
        "/api/v1/detections/ad",
        json=[{"asset_id": "DC-01", "service_principal_name": "MSSQLSvc/db01:1433"}],
    )
    assert findings.status_code == 200
    finding = findings.json()[0]
    risk = client.post("/api/v1/risk/correlate", json={"findings": [finding]})
    assert risk.status_code == 200
    assert risk.json()[0]["technique_id"] == "T1558.003"


def test_scenario_catalog_and_persisted_run() -> None:
    catalog = client.get("/api/v1/scenarios")
    assert catalog.status_code == 200
    scenario = next(item for item in catalog.json() if item["scenario_id"] == "ad.identity-exposure-baseline")
    assert "T1558.003" in scenario["technique_ids"]

    response = client.post(
        "/api/v1/scenarios/ad.identity-exposure-baseline/run",
        json={
            "scenario_id": "ad.identity-exposure-baseline",
            "observations": [{"asset_id": "DC-01", "service_principal_name": "MSSQLSvc/db01:1433"}],
            "alerts": [{"id": "alert-1", "rule": {"description": "T1558.003 Kerberoasting"}}],
            "dry_run": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_count"] == 1
    assert payload["coverage_percent"] == 50.0
    assert payload["gaps"] == ["T1558.004"]

    history = client.get("/api/v1/runs")
    assert history.status_code == 200
    assert any(item["run_id"] == payload["run_id"] for item in history.json())


def test_expert_campaign_operations_and_trends() -> None:
    campaign_response = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Q3 Identity Exposure Review",
            "objective": "Prioritize identity paths and close detection gaps in the isolated lab.",
            "owner": "blue-team",
            "scope_snapshot": ["192.168.56.0/24"],
        },
    )
    assert campaign_response.status_code == 201
    campaign = campaign_response.json()

    run_response = client.post(
        "/api/v1/scenarios/ad.identity-exposure-baseline/run",
        json={
            "scenario_id": "ad.identity-exposure-baseline",
            "observations": [{"asset_id": "DC-01", "service_principal_name": "MSSQLSvc/db01:1433"}],
            "alerts": [{"id": "alert-1", "rule": {"description": "T1558.003 Kerberoasting"}}],
            "dry_run": True,
        },
    )
    assert run_response.status_code == 200
    run_id = run_response.json()["run_id"]

    link_response = client.post(f"/api/v1/campaigns/{campaign['campaign_id']}/runs/{run_id}")
    assert link_response.status_code == 204

    evidence_response = client.post(
        "/api/v1/evidence",
        json={
            "campaign_id": campaign["campaign_id"],
            "run_id": run_id,
            "evidence_type": "wazuh_alert_export",
            "source": "lab/wazuh-alerts.json",
            "title": "Kerberoasting detection evidence",
            "sha256": "a" * 64,
            "technique_id": "T1558.003",
            "notes": "Synthetic evidence fixture for rule-tuning review.",
        },
    )
    assert evidence_response.status_code == 201

    remediation_response = client.post(
        "/api/v1/remediations",
        json={
            "campaign_id": campaign["campaign_id"],
            "finding_title": "Service principal on high-value account",
            "technique_id": "T1558.003",
            "recommendation": "Rotate the service account secret and add an identity-risk correlation rule.",
            "owner": "identity-team",
            "priority": "high",
        },
    )
    assert remediation_response.status_code == 201

    timeline = client.get(f"/api/v1/campaigns/{campaign['campaign_id']}/timeline")
    assert timeline.status_code == 200
    assert {item["event_type"] for item in timeline.json()} == {"assessment_run", "evidence", "remediation"}

    trend = client.get("/api/v1/trends/risk")
    tuning = client.get("/api/v1/detection-tuning")
    assert trend.status_code == 200 and trend.json()
    assert tuning.status_code == 200
    assert any(item["technique_id"] == "T1558.004" for item in tuning.json())


def test_purple_coverage_endpoint_returns_gap() -> None:
    response = client.post(
        "/api/v1/purple/analyze",
        json={
            "expected_technique_ids": ["T1558.003", "T1558.004"],
            "alerts": [{"id": "alert-1", "rule": {"description": "T1558.003 Kerberoasting"}}],
            "dry_run": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["coverage_percent"] == 50.0
    assert response.json()["gaps"] == ["T1558.004"]
