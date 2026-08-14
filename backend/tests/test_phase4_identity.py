import json
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.main import create_app
from app.schemas.identity import SessionRiskResponse
from fastapi.testclient import TestClient


def make_client(tmp_path: Path, *, risk_evaluator=None) -> tuple[TestClient, Settings]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / f'phase4-{uuid4().hex}.db'}",
        audit_log_path=str(tmp_path / f"phase4-{uuid4().hex}.jsonl"),
        auth_bootstrap_token="phase4-bootstrap-token",
        rate_limit_requests_per_minute=240,
    )
    return TestClient(create_app(settings, risk_evaluator=risk_evaluator)), settings


def bootstrap(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "phase4-bootstrap-token",
            "tenant_slug": "alpha",
            "tenant_name": "Alpha Security",
            "username": "alpha-admin",
            "password": "alpha-admin-password",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_user_and_login(
    client: TestClient,
    admin_headers: dict[str, str],
    username: str,
    roles: list[str],
) -> dict[str, str]:
    created = client.post(
        "/api/v1/auth/users",
        headers=admin_headers,
        json={"username": username, "password": f"{username}-password", "roles": roles},
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": "alpha", "username": username, "password": f"{username}-password"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_jit_policy_request_approval_is_tenant_scoped_and_audited(tmp_path: Path) -> None:
    client, settings = make_client(tmp_path)
    admin_headers = bootstrap(client)
    analyst_headers = create_user_and_login(client, admin_headers, "alpha-analyst", ["analyst"])

    policy = client.post(
        "/api/v1/auth/access-governance/policy-evaluate",
        headers=analyst_headers,
        json={
            "requested_scopes": ["read", "analyze"],
            "requested_ttl_minutes": 60,
            "reason": "Temporary analysis during an approved review window",
        },
    )
    assert policy.status_code == 200
    assert policy.json()["allowed"] is True
    assert policy.json()["requires_approval"] is True

    created = client.post(
        "/api/v1/auth/access-requests",
        headers=analyst_headers,
        json={
            "requested_scopes": ["read", "analyze"],
            "requested_ttl_minutes": 60,
            "reason": "Temporary analysis during an approved review window",
        },
    )
    assert created.status_code == 201
    request_id = created.json()["request_id"]
    assert created.json()["status"] == "pending"
    assert client.get("/api/v1/auth/access-requests", headers=analyst_headers).json()[0]["request_id"] == request_id
    assert client.get("/api/v1/auth/access-requests", headers=admin_headers).json()[0]["request_id"] == request_id

    decision = client.post(
        f"/api/v1/auth/access-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "comment": "Approved for the bounded review window"},
    )
    assert decision.status_code == 200
    assert decision.json()["status"] == "approved"

    self_request = client.post(
        "/api/v1/auth/access-requests",
        headers=admin_headers,
        json={
            "requested_scopes": ["read"],
            "requested_ttl_minutes": 30,
            "reason": "Temporary read access for a bounded review",
        },
    )
    assert self_request.status_code == 201
    self_decision = client.post(
        f"/api/v1/auth/access-requests/{self_request.json()['request_id']}/decision",
        headers=admin_headers,
        json={"decision": "approve", "comment": "self approval must fail"},
    )
    assert self_decision.status_code == 409

    audit_text = Path(settings.audit_log_path).read_text(encoding="utf-8")
    events = [json.loads(line) for line in audit_text.splitlines() if line.strip()]
    assert any(event["operation"] == "authz.policy_evaluated" for event in events)
    assert any(event["operation"] == "authz.jit_request_decided" for event in events)
    assert "Temporary analysis during an approved review window" not in audit_text
    assert "access_token" not in audit_text


def test_service_account_governance_inventory_revocation_and_review_are_bounded(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
    admin_headers = bootstrap(client)
    created = client.post(
        "/api/v1/auth/service-accounts",
        headers=admin_headers,
        json={"name": "audit-reader", "description": "Review account", "scopes": ["read", "view_audit"]},
    )
    assert created.status_code == 201
    service_account_id = created.json()["service_account"]["service_account_id"]

    inventory = client.get("/api/v1/auth/access-governance/service-accounts", headers=admin_headers)
    assert inventory.status_code == 200
    assert inventory.json()[0]["active_token_count"] == 1
    assert inventory.json()[0]["expired"] is False

    first_verification = client.get(
        f"/api/v1/auth/access-governance/service-accounts/{service_account_id}/revocation",
        headers=admin_headers,
    )
    assert first_verification.status_code == 200
    assert first_verification.json()["active_token_count"] == 1
    assert first_verification.json()["all_prior_tokens_revoked"] is False

    rotated = client.post(
        f"/api/v1/auth/service-accounts/{service_account_id}/rotate",
        headers=admin_headers,
    )
    assert rotated.status_code == 200
    second_verification = client.get(
        f"/api/v1/auth/access-governance/service-accounts/{service_account_id}/revocation",
        headers=admin_headers,
    )
    assert second_verification.json()["revoked_token_count"] == 1
    assert second_verification.json()["active_token_count"] == 1

    review = client.get(
        "/api/v1/auth/access-governance/least-privilege-review",
        headers=admin_headers,
    )
    assert review.status_code == 200
    assert len(review.json()["items"]) == 1
    assert review.json()["items"][0]["risk_level"] == "high"
    assert review.json()["items"][0]["excess_scopes"] == ["view_audit"]

    revoked = client.post(
        f"/api/v1/auth/service-accounts/{service_account_id}/revoke",
        headers=admin_headers,
    )
    assert revoked.status_code == 200
    final_verification = client.get(
        f"/api/v1/auth/access-governance/service-accounts/{service_account_id}/revocation",
        headers=admin_headers,
    )
    assert final_verification.json()["active_token_count"] == 0
    assert final_verification.json()["all_prior_tokens_revoked"] is True


def test_session_risk_evaluator_is_mockable_and_provider_side_effect_free(tmp_path: Path) -> None:
    class FixedRiskEvaluator:
        def evaluate(self, principal, context):
            assert principal.tenant_id
            assert context == {"source": "console"}
            return SessionRiskResponse(
                risk_level="medium",
                signals=["test_signal"],
                requires_step_up=True,
                evaluated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            )

    client, _ = make_client(tmp_path, risk_evaluator=FixedRiskEvaluator())
    admin_headers = bootstrap(client)
    result = client.get(
        "/api/v1/auth/access-governance/session-risk",
        headers={**admin_headers, "X-Client-Source": "console"},
    )
    assert result.status_code == 200
    assert result.json() == {
        "risk_level": "medium",
        "signals": ["test_signal"],
        "requires_step_up": True,
        "evaluated_at": result.json()["evaluated_at"],
    }
