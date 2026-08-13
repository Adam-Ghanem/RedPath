from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

DB_PATH = Path("/tmp") / f"redpath-ai02-{uuid4().hex}.db"
settings = Settings(
    database_url=f"sqlite:///{DB_PATH}",
    audit_log_path=f"/tmp/redpath-ai02-{uuid4().hex}.jsonl",
    auth_bootstrap_token="bootstrap-token-for-ai02-tests",
    rate_limit_requests_per_minute=240,
)
raw_client = TestClient(create_app(settings))

bootstrap = raw_client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "alpha",
        "tenant_name": "Alpha Security",
        "username": "alpha-admin",
        "password": "alpha-admin-password",
    },
)
assert bootstrap.status_code == 201
ADMIN_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def login(tenant_slug: str, username: str, password: str) -> dict[str, str]:
    response = raw_client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": tenant_slug, "username": username, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class AuthenticatedClient:
    def __init__(self, headers: dict[str, str]):
        self.headers = headers

    def get(self, path: str, **kwargs):
        return raw_client.get(path, headers=self.headers, **kwargs)

    def post(self, path: str, **kwargs):
        return raw_client.post(path, headers=self.headers, **kwargs)

    def patch(self, path: str, **kwargs):
        return raw_client.patch(path, headers=self.headers, **kwargs)


client = AuthenticatedClient(ADMIN_HEADERS)


def test_health_is_public_but_operational_api_requires_authentication() -> None:
    assert raw_client.get("/api/v1/health").status_code == 200
    assert raw_client.get("/api/v1/scope").status_code == 401
    assert client.get("/api/v1/scope").json()["dry_run_default"] is True


def test_identity_me_and_server_derived_actor_fields() -> None:
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alpha-admin"
    assert set(me.json()["roles"]) == {"platform_admin", "tenant_admin"}

    created = client.post(
        "/api/v1/auth/users",
        json={"username": "alpha-viewer", "password": "alpha-viewer-password", "roles": ["viewer"]},
    )
    assert created.status_code == 201
    viewer_headers = login("alpha", "alpha-viewer", "alpha-viewer-password")
    viewer = AuthenticatedClient(viewer_headers)
    assert viewer.get("/api/v1/scope").status_code == 200
    assert viewer.post("/api/v1/recon", json={"targets": ["192.168.56.10"], "dry_run": True}).status_code == 403

    campaign_response = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Identity attribution test",
            "objective": "Verify actor fields come from the authenticated principal.",
        },
    )
    assert campaign_response.status_code == 201
    assert campaign_response.json()["owner"] == "alpha-admin"


def test_bootstrap_is_single_use_and_platform_admin_can_provision_another_tenant() -> None:
    second_bootstrap = raw_client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "another",
            "tenant_name": "Another Security",
            "username": "another-admin",
            "password": "another-admin-password",
        },
    )
    assert second_bootstrap.status_code == 409

    tenant = client.post(
        "/api/v1/auth/tenants",
        json={
            "slug": "bravo",
            "name": "Bravo Security",
            "admin_username": "bravo-admin",
            "admin_password": "bravo-admin-password",
        },
    )
    assert tenant.status_code == 201
    assert tenant.json()["slug"] == "bravo"


def test_tenant_isolation_applies_to_campaigns_and_nested_resources() -> None:
    bravo = AuthenticatedClient(login("bravo", "bravo-admin", "bravo-admin-password"))
    alpha_campaign = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Alpha isolated campaign",
            "objective": "Confirm another tenant cannot enumerate or dereference this campaign.",
        },
    ).json()
    assert bravo.get("/api/v1/campaigns").status_code == 200
    assert bravo.get("/api/v1/campaigns").json() == []
    assert bravo.get(f"/api/v1/campaigns/{alpha_campaign['campaign_id']}/timeline").status_code == 404


def test_recon_rejects_out_of_scope_target_after_authentication() -> None:
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


def test_scenario_campaign_evidence_governance_and_tenant_scoped_reports() -> None:
    catalog = client.get("/api/v1/scenarios")
    assert catalog.status_code == 200
    scenario = next(item for item in catalog.json() if item["scenario_id"] == "ad.identity-exposure-baseline")

    run_response = client.post(
        f"/api/v1/scenarios/{scenario['scenario_id']}/run",
        json={
            "scenario_id": scenario["scenario_id"],
            "observations": [{"asset_id": "DC-01", "service_principal_name": "MSSQLSvc/db01:1433"}],
            "alerts": [{"id": "alert-1", "rule": {"description": "T1558.003 Kerberoasting"}}],
            "dry_run": True,
        },
    )
    assert run_response.status_code == 200
    run_id = run_response.json()["run_id"]

    campaign = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Q3 Identity Exposure Review",
            "objective": "Prioritize identity paths and close detection gaps in the isolated lab.",
            "scope_snapshot": ["192.168.56.0/24"],
        },
    ).json()
    assert client.post(f"/api/v1/campaigns/{campaign['campaign_id']}/runs/{run_id}").status_code == 204

    evidence = client.post(
        "/api/v1/evidence",
        json={
            "campaign_id": campaign["campaign_id"],
            "run_id": run_id,
            "evidence_type": "wazuh_alert_export",
            "source": "lab/wazuh-alerts.json",
            "title": "Kerberoasting detection evidence",
            "sha256": "a" * 64,
            "technique_id": "T1558.003",
        },
    )
    assert evidence.status_code == 201
    reviewed = client.patch(
        f"/api/v1/evidence/{evidence.json()['evidence_id']}/review",
        json={"review_status": "accepted", "notes": "Reviewed by the authenticated admin."},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["reviewer"] == "alpha-admin"

    remediation = client.post(
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
    assert remediation.status_code == 201
    lifecycle = client.patch(
        f"/api/v1/remediations/{remediation.json()['remediation_id']}/lifecycle",
        json={"status": "in_progress", "note": "Rule design started."},
    )
    assert lifecycle.status_code == 200

    acceptance = client.post(
        "/api/v1/risk-acceptances",
        json={
            "campaign_id": campaign["campaign_id"],
            "remediation_id": remediation.json()["remediation_id"],
            "technique_id": "T1558.003",
            "finding_title": "Detection gap requires a regression rule",
            "rationale": "Temporary acceptance while the rule is implemented and validated in the lab.",
            "expires_on": "2099-12-31",
        },
    )
    assert acceptance.status_code == 201
    assert acceptance.json()["approver"] == "alpha-admin"
    assert client.get(f"/api/v1/campaigns/{campaign['campaign_id']}/export").status_code == 200
    assert client.get("/api/v1/integrity/audit").json()["valid"] is True
