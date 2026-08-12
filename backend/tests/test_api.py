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
