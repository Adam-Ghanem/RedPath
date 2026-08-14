import json
from pathlib import Path
from uuid import uuid4

from app.core.authz import Principal as AttackPathPrincipal
from app.core.authz import authorize_tenant
from app.core.config import Settings
from app.core.ownership import OwnershipDenied, check_tenant, require_same_tenant
from app.core.request_context import Principal
from app.main import create_app
from fastapi.testclient import TestClient

PUBLIC_PATHS = {
    "/",
    "/api/v1/auth/bootstrap",
    "/api/v1/auth/token",
    "/api/v1/health",
    "/api/v1/health/live",
    "/api/v1/health/ready",
}

PROTECTED_PATHS = {
    "/api/v1/attack-paths/analyze",
    "/api/v1/copilot/explain",
    "/api/v1/risk/ai-assess",
    "/api/v1/auth/logout",
    "/api/v1/auth/me",
    "/api/v1/auth/sessions/revoke-all",
    "/api/v1/auth/tenants",
    "/api/v1/auth/users",
    "/api/v1/campaigns",
    "/api/v1/campaigns/{campaign_id}/export",
    "/api/v1/campaigns/{campaign_id}/runs/{run_id}",
    "/api/v1/campaigns/{campaign_id}/timeline",
    "/api/v1/detection-tuning",
    "/api/v1/detections/ad",
    "/api/v1/detections/evaluate",
    "/api/v1/detections/regressions/run",
    "/api/v1/detections/rules",
    "/api/v1/discovery/jobs",
    "/api/v1/discovery/jobs/{job_id}",
    "/api/v1/evidence",
    "/api/v1/evidence/{evidence_id}/manifest",
    "/api/v1/evidence/{evidence_id}/review",
    "/api/v1/graph/analyze",
    "/api/v1/integrations/{plugin_id}/analyze",
    "/api/v1/integrations/{plugin_id}/negotiate",
    "/api/v1/integrations/{plugin_id}/plan",
    "/api/v1/integrity/audit",
    "/api/v1/inventory/assets",
    "/api/v1/kpis/executive",
    "/api/v1/pcap/analyses",
    "/api/v1/pcap/analyses/{analysis_id}",
    "/api/v1/plugins",
    "/api/v1/plugins/catalog",
    "/api/v1/purple/analyze",
    "/api/v1/recon",
    "/api/v1/remediations",
    "/api/v1/remediations/sla",
    "/api/v1/remediations/{remediation_id}/lifecycle",
    "/api/v1/reports/pdf",
    "/api/v1/risk-acceptances",
    "/api/v1/risk/correlate",
    "/api/v1/runs",
    "/api/v1/scenarios",
    "/api/v1/scenarios/{scenario_id}/run",
    "/api/v1/scope",
    "/api/v1/scorecards/coverage",
    "/api/v1/siem/telemetry",
    "/api/v1/siem/telemetry/ingest",
    "/api/v1/techniques",
    "/api/v1/trends/risk",
}


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / f'phase2-{uuid4().hex}.db'}",
        audit_log_path=str(tmp_path / f"phase2-{uuid4().hex}.jsonl"),
        auth_bootstrap_token="phase2-bootstrap-token",
        rate_limit_requests_per_minute=240,
    )
    return TestClient(create_app(settings))


def bootstrap(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "phase2-bootstrap-token",
            "tenant_slug": "alpha",
            "tenant_name": "Alpha Security",
            "username": "alpha-admin",
            "password": "alpha-admin-password",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_every_api_route_is_explicitly_public_or_bearer_protected(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    openapi_paths = client.get("/openapi.json").json()["paths"]
    paths = set(openapi_paths)

    assert PUBLIC_PATHS <= paths | {"/"}
    assert PUBLIC_PATHS.isdisjoint(PROTECTED_PATHS)
    protected_paths = paths - PUBLIC_PATHS - {"/"}
    assert PROTECTED_PATHS <= protected_paths
    for path in protected_paths:
        operation = next(iter(openapi_paths[path].values()))
        assert operation.get("security"), path
    assert client.get("/api/v1/scope").status_code == 401
    assert client.get("/api/v1/health").status_code == 200


def test_logout_revokes_current_bearer_and_audits_without_token(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    headers = bootstrap(client)

    assert client.get("/api/v1/scope", headers=headers).status_code == 200
    logout = client.post("/api/v1/auth/logout", headers=headers)
    assert logout.status_code == 200
    assert logout.json() == {"revoked_sessions": 1}

    denied = client.get("/api/v1/scope", headers=headers)
    assert denied.status_code == 401
    assert denied.json()["detail"] == "Authentication required"
    assert denied.json()["error_code"] == "authentication_required"
    assert denied.headers["x-request-id"] == denied.json()["request_id"]
    audit_path = next(path for path in tmp_path.glob("*.jsonl"))
    audit_text = audit_path.read_text(encoding="utf-8")
    assert "auth.logout" in audit_text
    assert headers["Authorization"].split()[-1] not in audit_text


def test_revoke_all_invalidates_parallel_sessions(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    first_headers = bootstrap(client)
    second = client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": "alpha", "username": "alpha-admin", "password": "alpha-admin-password"},
    )
    assert second.status_code == 200
    second_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}

    revoked = client.post("/api/v1/auth/sessions/revoke-all", headers=first_headers)
    assert revoked.status_code == 200
    assert revoked.json()["revoked_sessions"] == 2
    assert client.get("/api/v1/auth/me", headers=first_headers).status_code == 401
    assert client.get("/api/v1/auth/me", headers=second_headers).status_code == 401


def test_authorization_failures_are_generic_and_audited(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    admin_headers = bootstrap(client)
    created = client.post(
        "/api/v1/auth/users",
        headers=admin_headers,
        json={"username": "alpha-viewer", "password": "alpha-viewer-password", "roles": ["viewer"]},
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": "alpha", "username": "alpha-viewer", "password": "alpha-viewer-password"},
    )
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    denied = client.post(
        "/api/v1/recon",
        headers=viewer_headers,
        json={"targets": ["192.168.56.10"], "profile": "safe", "dry_run": True},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Insufficient authorization"
    assert denied.json()["error_code"] == "authorization_denied"
    assert "192.168.56.10" not in denied.text
    audit_path = next(path for path in tmp_path.glob("*.jsonl"))
    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(event["operation"] == "authz.permission_denied" for event in events)
    assert any(event["operation"] == "api.authorization_failure" for event in events)


def test_shared_ownership_helpers_fail_closed_for_cross_tenant_resources() -> None:
    principal = Principal(
        user_id="user-a",
        username="analyst-a",
        tenant_id="tenant-a",
        tenant_slug="tenant-a",
        roles=("analyst",),
        session_version=1,
    )

    assert check_tenant("tenant-a", principal).allowed is True
    assert check_tenant("tenant-b", principal).reason == "tenant_mismatch"
    try:
        require_same_tenant(type("Resource", (), {"tenant_id": "tenant-b"})(), principal)
    except KeyError as exc:
        assert str(exc) == "'Resource not found'"
    else:
        raise AssertionError("cross-tenant resource was accepted")

    attack_principal = AttackPathPrincipal(
        subject="analyst-a",
        roles=frozenset({"analyst"}),
        tenant_ids=frozenset({"tenant-a"}),
    )
    try:
        authorize_tenant(attack_principal, "tenant-b")
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 403
    else:
        raise AssertionError("attack-path cross-tenant resource was accepted")

    try:
        raise OwnershipDenied("internal owner detail")
    except OwnershipDenied:
        pass
