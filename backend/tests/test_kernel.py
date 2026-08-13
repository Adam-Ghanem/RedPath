import pytest
from app.core.config import Settings
from app.kernel.contracts import IntegrationContext
from app.main import create_app
from app.plugins.base import PluginManifest
from app.plugins.registry import PluginRegistry, RegistryPlugin
from fastapi.testclient import TestClient
from pydantic import ValidationError
from uuid import uuid4


settings = Settings(
    database_url=f"sqlite:////tmp/redpath-kernel-{uuid4().hex}.db",
    audit_log_path=f"/tmp/redpath-kernel-{uuid4().hex}.jsonl",
    auth_bootstrap_token="kernel-test-bootstrap-token",
)
client = TestClient(create_app(settings))
bootstrap = client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "kernel",
        "tenant_name": "Kernel Test Tenant",
        "username": "kernel-admin",
        "password": "kernel-admin-password",
    },
)
assert bootstrap.status_code == 201
AUTH_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def test_context_is_versioned_frozen_and_rejects_control_characters() -> None:
    context = IntegrationContext(tenant_id="tenant-a", actor="analyst-1", request_id="request-1", targets=("192.168.56.10",))
    assert context.schema_version == "1.0"
    with pytest.raises(ValidationError):
        context.tenant_id = "tenant-b"
    with pytest.raises(ValidationError):
        IntegrationContext(tenant_id="tenant-a", actor="analyst-1", request_id="request-1", targets=("192.168.56.10\n--unsafe",))


def test_registry_rejects_duplicate_and_non_read_only_plugins() -> None:
    registry = PluginRegistry()
    manifest = PluginManifest(plugin_id="custom.read_only", name="Custom", version="1.0.0", capabilities=("analysis",))
    registry.register(RegistryPlugin(manifest))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(RegistryPlugin(manifest))
    unsafe = PluginManifest(plugin_id="custom.write_action", name="Unsafe", version="1.0.0", capabilities=("analysis",), read_only=False)
    with pytest.raises(ValueError, match="read-only"):
        registry.register(RegistryPlugin(unsafe))


def test_integration_plan_is_declarative_and_audited() -> None:
    response = client.post("/api/v1/integrations/recon.safe_inventory/plan", json={"tenant_id": "tenant-a", "actor": "analyst-1", "request_id": "plan-1", "targets": ["192.168.56.10"], "dry_run": True}, headers=AUTH_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "1.0"
    assert payload["dry_run"] is True
    assert payload["actions"][0]["read_only"] is True
    assert "argv" not in payload["actions"][0]


def test_integration_analyze_enforces_scope_and_tenant_isolation() -> None:
    out_of_scope = client.post("/api/v1/integrations/ad.observation_analyzer/analyze", json={"tenant_id": "tenant-a", "actor": "analyst-1", "targets": ["8.8.8.8"], "observations": []}, headers=AUTH_HEADERS)
    assert out_of_scope.status_code == 403
    tenant_mismatch = client.post("/api/v1/integrations/ad.observation_analyzer/analyze", json={"tenant_id": "tenant-a", "actor": "analyst-1", "request_id": "analysis-1", "observations": [{"observation_id": "obs-1", "tenant_id": "tenant-b", "source": "fixture", "attributes": {"technique_id": "T1558.003"}}]}, headers=AUTH_HEADERS)
    assert tenant_mismatch.status_code == 422
    assert "tenant_id" in tenant_mismatch.json()["detail"]


def test_unknown_plugin_is_not_executable() -> None:
    response = client.post("/api/v1/integrations/unknown.plugin/plan", json={"tenant_id": "tenant-a", "actor": "analyst-1"}, headers=AUTH_HEADERS)
    assert response.status_code == 404
