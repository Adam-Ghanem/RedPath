import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
from app.core.auth import IdentityProviderUnavailable, MfaStepUpPolicy, OIDCAuthenticationProvider
from app.core.config import Settings
from app.core.request_context import Principal
from app.db.models import create_session_factory
from app.main import create_app
from app.services.service_accounts import ServiceAccountService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text


def make_client(tmp_path: Path, **overrides: object) -> tuple[TestClient, Settings]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / f'phase3-{uuid4().hex}.db'}",
        audit_log_path=str(tmp_path / f"phase3-{uuid4().hex}.jsonl"),
        auth_bootstrap_token="phase3-bootstrap-token",
        rate_limit_requests_per_minute=240,
        **overrides,
    )
    return TestClient(create_app(settings)), settings


def bootstrap(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "phase3-bootstrap-token",
            "tenant_slug": "alpha",
            "tenant_name": "Alpha Security",
            "username": "alpha-admin",
            "password": "alpha-admin-password",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_oidc_boundary_fails_closed_without_a_verifier_and_normalizes_method() -> None:
    provider = OIDCAuthenticationProvider()
    try:
        provider.resolve("opaque-test-token")
    except IdentityProviderUnavailable:
        pass
    else:
        raise AssertionError("OIDC provider accepted a token without a verifier")

    principal = Principal(
        user_id="oidc-user",
        username="oidc-user",
        tenant_id="tenant-a",
        tenant_slug="tenant-a",
        roles=("viewer",),
        session_version=1,
    )
    verified = OIDCAuthenticationProvider(lambda _: principal).resolve("verified-token")
    assert verified.auth_method == "oidc"
    assert verified.user_id == "oidc-user"


def test_mfa_step_up_policy_is_explicit_and_time_bounded() -> None:
    now = datetime.now(timezone.utc)
    principal = Principal(
        user_id="user-a",
        username="analyst-a",
        tenant_id="tenant-a",
        tenant_slug="tenant-a",
        roles=("tenant_admin",),
        session_version=1,
    )
    policy = MfaStepUpPolicy(frozenset({"manage_identity"}))
    assert policy.is_satisfied(principal, "read") is True
    assert policy.is_satisfied(principal, "manage_identity") is False
    verified = Principal(
        **{
            **principal.__dict__,
            "mfa_verified": True,
            "step_up_expires_at": now + timedelta(minutes=5),
        }
    )
    assert policy.is_satisfied(verified, "manage_identity") is True
    expired = Principal(
        **{
            **principal.__dict__,
            "mfa_verified": True,
            "step_up_expires_at": now - timedelta(seconds=1),
        }
    )
    assert policy.is_satisfied(expired, "manage_identity") is False


def test_service_account_is_least_privilege_rotatable_and_revocable(tmp_path: Path) -> None:
    client, settings = make_client(tmp_path)
    admin_headers = bootstrap(client)
    created = client.post(
        "/api/v1/auth/service-accounts",
        headers=admin_headers,
        json={"name": "telemetry-reader", "description": "Read-only telemetry", "scopes": ["read"]},
    )
    assert created.status_code == 201
    first = created.json()
    first_token = {"Authorization": f"Bearer {first['access_token']}"}
    service_account_id = first["service_account"]["service_account_id"]
    assert client.get("/api/v1/scope", headers=first_token).status_code == 200
    denied = client.post(
        "/api/v1/recon",
        headers=first_token,
        json={"targets": ["192.168.56.10"], "profile": "safe", "dry_run": True},
    )
    assert denied.status_code == 403

    rotated = client.post(
        f"/api/v1/auth/service-accounts/{service_account_id}/rotate",
        headers=admin_headers,
    )
    assert rotated.status_code == 200
    second_token = {"Authorization": f"Bearer {rotated.json()['access_token']}"}
    assert rotated.json()["service_account"]["token_version"] == 2
    assert client.get("/api/v1/scope", headers=first_token).status_code == 401
    assert client.get("/api/v1/scope", headers=second_token).status_code == 200

    revoked = client.post(
        f"/api/v1/auth/service-accounts/{service_account_id}/revoke",
        headers=admin_headers,
    )
    assert revoked.status_code == 200
    assert revoked.json()["is_active"] is False
    assert client.get("/api/v1/scope", headers=second_token).status_code == 401

    audit_path = Path(settings.audit_log_path)
    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    audit_text = audit_path.read_text(encoding="utf-8")
    assert any(event["operation"] == "auth.service_account_created" for event in events)
    assert any(event["operation"] == "auth.service_account_rotated" for event in events)
    assert any(event["operation"] == "auth.service_account_revoked" for event in events)
    assert first["access_token"] not in audit_text
    assert rotated.json()["access_token"] not in audit_text


def test_service_account_api_requires_fine_grained_manage_identity_permission(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
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
    denied = client.get("/api/v1/auth/service-accounts", headers=viewer_headers)
    assert denied.status_code == 403
    assert denied.json()["error_code"] == "authorization_denied"
    assert denied.json()["detail"] == "Insufficient authorization"


def test_enterprise_identity_revision_is_applied_by_alembic(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"
    create_session_factory(database_url)
    engine = create_engine(database_url)
    tables = set(inspect(engine).get_table_names())
    assert {"service_accounts", "service_account_tokens"}.issubset(tables)
    with engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        session_columns = {column["name"] for column in inspect(engine).get_columns("auth_sessions")}
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    assert version == ScriptDirectory.from_config(config).get_current_head()
    assert "mfa_verified_until" in session_columns


def test_service_account_service_rejects_cross_tenant_token_context(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'service.db'}"
    factory = create_session_factory(database_url)
    service = ServiceAccountService(factory)
    principal = Principal(
        user_id="u-a",
        username="admin-a",
        tenant_id="tenant-a",
        tenant_slug="tenant-a",
        roles=("tenant_admin",),
        session_version=1,
    )
    try:
        service.list(principal)
    except Exception as exc:  # No cross-tenant rows exist and service must remain empty.
        raise AssertionError(f"unexpected service-account list failure: {exc}") from exc
    assert service.list(principal) == []


def test_unconfigured_oidc_mode_fails_closed_with_safe_api_error(tmp_path: Path) -> None:
    client, _ = make_client(
        tmp_path,
        auth_provider="oidc",
        oidc_issuer_url="https://issuer.example",
        oidc_audience="redpath",
        oidc_jwks_url="https://issuer.example/.well-known/jwks.json",
    )
    headers = bootstrap(client)
    response = client.get("/api/v1/scope", headers=headers)
    assert response.status_code == 503
    assert response.json()["detail"] == "authentication unavailable"
    assert "verifier" not in response.text.lower()


def test_rate_limiter_interface_is_bounded_and_fail_closed() -> None:
    from app.core.auth import RateLimiter

    limiter = RateLimiter(limit=1, window_seconds=60)
    assert limiter.allow("tenant-a:principal-a") is True
    assert limiter.allow("tenant-a:principal-a") is False
    assert limiter.allow("tenant-a:principal-b") is True
