from __future__ import annotations

from uuid import uuid4

import pytest
from app.core.config import Settings
from app.kernel.contracts import (
    IntegrationContext,
    IntegrationErrorCode,
    IntegrationKernelError,
    ModuleKind,
    PaginationRequest,
)
from app.kernel.service import IntegrationKernel
from app.main import create_app
from app.plugins.registry import PluginRegistry
from fastapi.testclient import TestClient
from fixtures.kernel_modules import KERNEL_MODULE_FIXTURES, fixture_context, fixture_registry
from pydantic import ValidationError

settings = Settings(
    database_url=f"sqlite:////tmp/redpath-phase2-extension-{uuid4().hex}.db",
    audit_log_path=f"/tmp/redpath-phase2-extension-{uuid4().hex}.jsonl",
    auth_bootstrap_token="phase2-extension-bootstrap-token",
)
client = TestClient(create_app(settings))
bootstrap = client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "phase2-extension",
        "tenant_name": "Phase 2 Extension Test Tenant",
        "username": "phase2-admin",
        "password": "phase2-admin-password",
    },
)
assert bootstrap.status_code == 201
AUTH_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


class AuditSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def __call__(self, operation: str, details: dict) -> None:
        self.events.append((operation, details))


def test_all_defensive_module_fixtures_negotiate_exact_contract_and_plan_safely() -> None:
    registry = fixture_registry()
    audit = AuditSink()
    kernel = IntegrationKernel(registry=registry, audit_recorder=audit)

    assert {fixture.module_kind for fixture in KERNEL_MODULE_FIXTURES} == {
        ModuleKind.PCAP,
        ModuleKind.TELEMETRY,
        ModuleKind.DISCOVERY,
        ModuleKind.DETECTION,
        ModuleKind.GRAPH,
        ModuleKind.CASE,
    }

    for fixture in KERNEL_MODULE_FIXTURES:
        context = fixture_context(fixture)
        decision = kernel.negotiate(fixture.plugin_id, context)
        plan = kernel.plan(fixture.plugin_id, context)

        assert decision.compatible is True
        assert decision.selected_contract_version == "1.0"
        assert decision.capabilities[0].module_kind == fixture.module_kind
        assert plan.dry_run is True
        assert all(action.read_only and action.dry_run for action in plan.actions)
        assert all("argv" not in action.model_dump() for action in plan.actions)
        assert all("command" not in action.model_dump() for action in plan.actions)

    assert len(audit.events) == len(KERNEL_MODULE_FIXTURES) * 2


def test_negotiation_rejects_incompatible_version_and_unknown_capability() -> None:
    registry = fixture_registry()
    kernel = IntegrationKernel(registry=registry)
    fixture = KERNEL_MODULE_FIXTURES[0]
    base_context = fixture_context(fixture)

    incompatible = kernel.negotiate(
        fixture.plugin_id,
        base_context.model_copy(update={"contract_version": "9.0"}),
    )
    assert incompatible.compatible is False
    assert incompatible.error is not None
    assert incompatible.error.code == IntegrationErrorCode.INCOMPATIBLE_CONTRACT_VERSION

    with pytest.raises(IntegrationKernelError) as exc_info:
        kernel.plan(
            fixture.plugin_id,
            base_context.model_copy(update={"requested_capabilities": ("unapproved.operation",)}),
        )
    assert exc_info.value.status_code == 422
    assert exc_info.value.error.code == IntegrationErrorCode.UNSUPPORTED_CAPABILITY


def test_structured_unknown_plugin_error_contains_no_raw_input() -> None:
    kernel = IntegrationKernel(registry=PluginRegistry())

    with pytest.raises(IntegrationKernelError) as exc_info:
        kernel.plan(
            "unknown.plugin",
            IntegrationContext(
                tenant_id="tenant-a",
                actor="server-derived-analyst",
                request_id="request-unknown",
                dry_run=True,
            ),
        )

    assert exc_info.value.status_code == 404
    error = exc_info.value.error
    assert error.code == IntegrationErrorCode.PLUGIN_NOT_FOUND
    assert "unknown.plugin" not in error.message
    assert error.plugin_id == "unknown.plugin"


def test_fixture_analysis_enforces_tenant_isolation() -> None:
    fixture = KERNEL_MODULE_FIXTURES[1]
    kernel = IntegrationKernel(registry=fixture_registry())
    context = fixture_context(fixture)

    result = kernel.analyze(fixture.plugin_id, context, [fixture.observation()])
    assert result.observation_count == 1

    with pytest.raises(IntegrationKernelError) as exc_info:
        kernel.analyze(fixture.plugin_id, context, [fixture.observation(tenant_id="tenant-b")])
    assert exc_info.value.error.code == IntegrationErrorCode.TENANT_MISMATCH
    assert exc_info.value.status_code == 422


def test_pagination_is_bounded_and_cursored() -> None:
    registry = fixture_registry()
    first = registry.catalog_page(PaginationRequest(limit=2))
    second = registry.catalog_page(PaginationRequest(limit=2, cursor=first.pagination.next_cursor))

    assert len(first.items) == 2
    assert first.pagination.has_more is True
    assert second.items[0].plugin_id != first.items[0].plugin_id
    assert second.schema_version == "1.0"

    with pytest.raises(ValidationError):
        PaginationRequest(limit=101)


def test_fixture_registry_rejects_mutating_or_non_dry_run_plugins() -> None:
    fixture = KERNEL_MODULE_FIXTURES[0]
    manifest = fixture.plugin().manifest
    assert manifest.read_only is True
    assert manifest.supports_dry_run is True


@pytest.mark.parametrize(
    "fixture",
    KERNEL_MODULE_FIXTURES,
    ids=lambda fixture: fixture.module_kind.value,
)
def test_each_module_fixture_accepts_normalized_observation(fixture) -> None:
    kernel = IntegrationKernel(registry=fixture_registry())

    result = kernel.analyze(
        fixture.plugin_id,
        fixture_context(fixture),
        [fixture.observation()],
    )

    assert result.schema_version == "1.0"
    assert result.plugin_id == fixture.plugin_id
    assert result.observation_count == 1



def test_extension_catalog_route_is_protected_and_paginated() -> None:
    unauthenticated = client.get("/api/v1/plugins/catalog?limit=2")
    assert unauthenticated.status_code == 401

    response = client.get("/api/v1/plugins/catalog?limit=2", headers=AUTH_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "1.0"
    assert len(payload["items"]) == 2
    assert payload["pagination"]["has_more"] is True


def test_negotiation_route_returns_compatibility_and_structured_error() -> None:
    compatible = client.post(
        "/api/v1/integrations/recon.safe_inventory/negotiate",
        json={
            "request_id": "route-negotiate-1",
            "contract_version": "1.0",
            "requested_capabilities": ["asset_discovery"],
            "dry_run": True,
        },
        headers=AUTH_HEADERS,
    )
    assert compatible.status_code == 200
    assert compatible.json()["compatible"] is True
    assert compatible.json()["capabilities"][0]["module_kind"] == "discovery"

    incompatible = client.post(
        "/api/v1/integrations/recon.safe_inventory/negotiate",
        json={
            "request_id": "route-negotiate-2",
            "contract_version": "9.0",
            "requested_capabilities": ["asset_discovery"],
            "dry_run": True,
        },
        headers=AUTH_HEADERS,
    )
    assert incompatible.status_code == 200
    assert incompatible.json()["compatible"] is False
    assert incompatible.json()["error"]["code"] == "incompatible_contract_version"


def test_plan_route_keeps_actor_server_derived_and_errors_structured() -> None:
    response = client.post(
        "/api/v1/integrations/recon.safe_inventory/plan",
        json={
            "tenant_id": "client-supplied-tenant-must-be-ignored",
            "actor": "client-supplied-actor-must-be-ignored",
            "request_id": "route-plan-1",
            "targets": ["192.168.56.10"],
            "dry_run": True,
        },
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 200
    assert "client-supplied-actor-must-be-ignored" not in response.text

    unknown = client.post(
        "/api/v1/integrations/unknown.plugin/plan",
        json={"tenant_id": "client", "actor": "client", "request_id": "route-plan-2"},
        headers=AUTH_HEADERS,
    )
    assert unknown.status_code == 404
    assert unknown.json()["detail"]["code"] == "plugin_not_found"
    assert "unknown.plugin" not in unknown.json()["detail"]["message"]
