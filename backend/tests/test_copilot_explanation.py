from __future__ import annotations

from pathlib import Path

import pytest
from app.core.config import Settings
from app.main import create_app
from app.schemas.contracts import (
    CopilotAttackPathSummary,
    CopilotDetectionEvidence,
    CopilotExplainRequest,
    CopilotProviderOutput,
)
from app.services.copilot_explanation import (
    CopilotExplanationService,
    ProviderUnavailable,
)
from fastapi.testclient import TestClient


class RecordingProvider:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def explain(self, context: dict[str, object]) -> CopilotProviderOutput:
        self.calls.append(context)
        return CopilotProviderOutput(
            explanation=(
                "The bounded evidence supports review of the modeled control.\n\nNo other facts are established."
            ),
            next_actions=["Review the evidence-backed control."],
            confidence_note="Grounded only in sanitized context.",
        )


class FailingProvider:
    def explain(self, context: dict[str, object]) -> CopilotProviderOutput:
        raise ProviderUnavailable("mock provider unavailable")


def settings(*, enabled: bool = False) -> Settings:
    return Settings(
        ai_features_enabled=enabled,
        ai_api_key="env-only-test-key",
        ai_api_base="https://provider.invalid/v1",
        ai_cache_ttl_seconds=300,
        ai_cache_max_entries=4,
    )


def attack_path_request(
    *,
    asset_ids: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    signal: str = "T1059 observed lateral movement",
) -> CopilotExplainRequest:
    return CopilotExplainRequest(
        subject_type="attack_path",
        subject_id="path-client-only",
        title="Sensitive title should not leave the service",
        deterministic_score=82.0,
        centrality=0.85,
        deterministic_tier="high",
        attack_path=CopilotAttackPathSummary(
            risk_score=82.0,
            centrality=0.85,
            hop_count=3,
            asset_count=len(asset_ids or ["asset-a"]),
            evidence_count=len(evidence_ids or ["evidence-a"]),
            asset_ids=asset_ids or ["asset-a"],
            evidence_ids=evidence_ids or ["evidence-a"],
            technique_ids=["T1059"],
            rationale=signal,
        ),
        evidence=[
            CopilotDetectionEvidence(
                evidence_id=(evidence_ids or ["evidence-a"])[0],
                severity="high",
                technique_id="T1059",
                signal=signal,
            )
        ],
    )


def test_disabled_state_returns_deterministic_fallback_without_provider_call() -> None:
    provider = RecordingProvider()
    service = CopilotExplanationService(settings(enabled=False), provider=provider)

    result = service.explain(
        attack_path_request(),
        authorized_tenant_id="tenant-a",
        authorized_asset_ids={"asset-a"},
        authorized_evidence_ids={"evidence-a"},
    )

    assert result.ai_status == "disabled"
    assert result.fallback_reason == "ai_disabled"
    assert result.data_egress == "none"
    assert result.deterministic_score == 82.0
    assert provider.calls == []


def test_provider_failure_returns_deterministic_fallback() -> None:
    service = CopilotExplanationService(settings(enabled=True), provider=FailingProvider())

    result = service.explain(
        attack_path_request(),
        authorized_tenant_id="tenant-a",
        authorized_asset_ids={"asset-a"},
        authorized_evidence_ids={"evidence-a"},
    )

    assert result.ai_status == "fallback"
    assert result.fallback_reason == "provider_unavailable"
    assert result.tier == "critical"
    assert "unprovided facts cannot be asserted" in result.confidence_note


def test_cache_is_tenant_scoped_and_does_not_share_identical_payloads() -> None:
    provider = RecordingProvider()
    service = CopilotExplanationService(settings(enabled=True), provider=provider)
    request = attack_path_request()

    first = service.explain(
        request,
        authorized_tenant_id="tenant-a",
        authorized_asset_ids={"asset-a"},
        authorized_evidence_ids={"evidence-a"},
    )
    second = service.explain(
        request,
        authorized_tenant_id="tenant-a",
        authorized_asset_ids={"asset-a"},
        authorized_evidence_ids={"evidence-a"},
    )
    other_tenant = service.explain(
        request,
        authorized_tenant_id="tenant-b",
        authorized_asset_ids={"asset-a"},
        authorized_evidence_ids={"evidence-a"},
    )

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert other_tenant.cache_hit is False
    assert first.context_sha256 != other_tenant.context_sha256
    assert len(provider.calls) == 2


def test_cross_tenant_asset_or_evidence_reference_is_rejected() -> None:
    service = CopilotExplanationService(settings(enabled=False))

    with pytest.raises(PermissionError, match="assets outside"):
        service.explain(
            attack_path_request(asset_ids=["asset-other"]),
            authorized_tenant_id="tenant-a",
            authorized_asset_ids={"asset-a"},
            authorized_evidence_ids={"evidence-a"},
        )

    with pytest.raises(PermissionError, match="evidence outside"):
        service.explain(
            attack_path_request(evidence_ids=["evidence-other"]),
            authorized_tenant_id="tenant-a",
            authorized_asset_ids={"asset-a"},
            authorized_evidence_ids={"evidence-a"},
        )


def test_provider_context_is_minimized_and_identifier_free() -> None:
    provider = RecordingProvider()
    service = CopilotExplanationService(settings(enabled=True), provider=provider)
    request = attack_path_request(
        signal=(
            "asset_id=asset-a hostname=db01.corp.local host=db01 user=alice "
            "username=alice account=alice principal=alice evidence_id=evidence-a "
            "ip=192.0.2.10 password=secret T1059 observed lateral movement"
        )
    )

    service.explain(
        request,
        authorized_tenant_id="tenant-a",
        authorized_asset_ids={"asset-a"},
        authorized_evidence_ids={"evidence-a"},
    )

    assert len(provider.calls) == 1
    serialized = str(provider.calls[0])
    sensitive_values = (
        "path-client-only",
        "Sensitive title",
        "asset-a",
        "evidence-a",
        "db01",
        "alice",
        "192.0.2.10",
        "secret",
    )
    for sensitive in sensitive_values:
        assert sensitive not in serialized
    assert "T1059" in serialized
    assert "lateral" in serialized


def test_risk_ai_assess_binds_references_to_authenticated_tenant(tmp_path: Path) -> None:
    config = Settings(
        database_url=f"sqlite:///{tmp_path / 'copilot-security.db'}",
        audit_log_path=str(tmp_path / "copilot-security.jsonl"),
        auth_bootstrap_token="copilot-security-token",
        ai_features_enabled=False,
    )
    client = TestClient(create_app(config))
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": config.auth_bootstrap_token,
            "tenant_slug": "copilot-security",
            "tenant_name": "Copilot Security Tenant",
            "username": "copilot-security-admin",
            "password": "copilot-security-password",
        },
    )
    assert bootstrap.status_code == 201
    headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
    response = client.post(
        "/api/v1/risk/ai-assess",
        json=attack_path_request(asset_ids=["asset-other"], evidence_ids=["evidence-other"]).model_dump(),
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient authorization"


def test_copilot_api_is_protected_and_disabled_by_default(tmp_path: Path) -> None:
    config = Settings(
        database_url=f"sqlite:///{tmp_path / 'copilot-disabled.db'}",
        audit_log_path=str(tmp_path / "copilot-disabled.jsonl"),
        auth_bootstrap_token="copilot-disabled-token",
    )
    client = TestClient(create_app(config))
    unauthenticated = client.post("/api/v1/copilot/explain", json={})
    assert unauthenticated.status_code == 401

    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": config.auth_bootstrap_token,
            "tenant_slug": "copilot-disabled",
            "tenant_name": "Copilot Disabled Tenant",
            "username": "copilot-disabled-admin",
            "password": "copilot-disabled-password",
        },
    )
    headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
    response = client.post(
        "/api/v1/copilot/explain",
        json=CopilotExplainRequest(
            subject_type="finding",
            subject_id="finding-1",
            deterministic_score=40,
            deterministic_tier="medium",
        ).model_dump(),
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["ai_status"] == "disabled"
    assert response.json()["data_egress"] == "none"
