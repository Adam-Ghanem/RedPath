from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from app.core.config import Settings
from app.db.models import AttackPathAnalysis, EvidenceItem, Finding, create_session_factory
from app.main import create_app
from app.schemas.contracts import (
    CopilotAttackPathSummary,
    CopilotDetectionEvidence,
    CopilotExplainRequest,
    CopilotProviderOutput,
    CopilotResolvedContext,
)
from app.services.copilot_explanation import CopilotExplanationService, ProviderUnavailable
from fastapi.testclient import TestClient
from pydantic import ValidationError


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


def service_settings(*, enabled: bool = False) -> Settings:
    return Settings(
        ai_features_enabled=enabled,
        ai_api_key="env-only-test-key",
        ai_api_base="https://provider.invalid/v1",
        ai_cache_ttl_seconds=300,
        ai_cache_max_entries=4,
    )


def resolved_finding(*, tenant_id: str = "tenant-a", source_id: str = "finding-a") -> CopilotResolvedContext:
    return CopilotResolvedContext(
        tenant_id=tenant_id,
        source_type="finding",
        source_id=source_id,
        deterministic_score=25.0,
        centrality=0.5,
        deterministic_tier="low",
        evidence=[
            CopilotDetectionEvidence(
                evidence_id="evidence-a",
                severity="low",
                technique_id="T1059",
                signal="asset_id=asset-a host=db01.corp.local user=alice T1059 observed lateral movement",
            )
        ],
    )


def resolved_path(*, tenant_id: str = "tenant-a", source_id: str = "path-a") -> CopilotResolvedContext:
    return CopilotResolvedContext(
        tenant_id=tenant_id,
        source_type="attack_path",
        source_id=source_id,
        deterministic_score=82.0,
        centrality=0.85,
        deterministic_tier="critical",
        attack_path=CopilotAttackPathSummary(
            risk_score=82.0,
            centrality=0.85,
            hop_count=3,
            asset_count=1,
            evidence_count=1,
            asset_ids=["asset-a"],
            evidence_ids=["evidence-a"],
            technique_ids=["T1059"],
            rationale="asset_id=asset-a hostname=db01.corp.local principal=alice T1059 lateral movement",
        ),
        evidence=[
            CopilotDetectionEvidence(
                evidence_id="evidence-a",
                severity="critical",
                technique_id="T1059",
                signal="asset_id=asset-a host=db01 user=alice password=secret 192.0.2.10 T1059",
            )
        ],
    )


def test_disabled_state_returns_deterministic_fallback_without_provider_call() -> None:
    provider = RecordingProvider()
    service = CopilotExplanationService(service_settings(enabled=False), provider=provider)

    result = service.explain(resolved_path(), authorized_tenant_id="tenant-a")

    assert result.ai_status == "disabled"
    assert result.fallback_reason == "ai_disabled"
    assert result.data_egress == "none"
    assert result.deterministic_score == 82.0
    assert provider.calls == []


def test_provider_failure_returns_deterministic_fallback() -> None:
    service = CopilotExplanationService(service_settings(enabled=True), provider=FailingProvider())

    result = service.explain(resolved_path(), authorized_tenant_id="tenant-a")

    assert result.ai_status == "fallback"
    assert result.fallback_reason == "provider_unavailable"
    assert result.tier == "critical"
    assert "unprovided facts cannot be asserted" in result.confidence_note


def test_cache_is_tenant_scoped_and_does_not_share_identical_context() -> None:
    provider = RecordingProvider()
    service = CopilotExplanationService(service_settings(enabled=True), provider=provider)

    first = service.explain(resolved_path(tenant_id="tenant-a"), authorized_tenant_id="tenant-a")
    second = service.explain(resolved_path(tenant_id="tenant-a"), authorized_tenant_id="tenant-a")
    other_tenant = service.explain(resolved_path(tenant_id="tenant-b"), authorized_tenant_id="tenant-b")

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert other_tenant.cache_hit is False
    assert first.context_sha256 != other_tenant.context_sha256
    assert len(provider.calls) == 2


def test_service_rejects_context_for_another_authenticated_tenant() -> None:
    service = CopilotExplanationService(service_settings(enabled=False))

    with pytest.raises(PermissionError, match="does not match authenticated tenant"):
        service.explain(resolved_path(tenant_id="tenant-a"), authorized_tenant_id="tenant-b")


def test_provider_context_is_minimized_and_identifier_free() -> None:
    provider = RecordingProvider()
    service = CopilotExplanationService(service_settings(enabled=True), provider=provider)

    service.explain(resolved_path(), authorized_tenant_id="tenant-a")

    assert len(provider.calls) == 1
    serialized = json.dumps(provider.calls[0], sort_keys=True)
    for sensitive in (
        "path-a",
        "finding-a",
        "asset-a",
        "evidence-a",
        "db01",
        "alice",
        "192.0.2.10",
        "secret",
    ):
        assert sensitive not in serialized
    assert "T1059" in serialized
    assert "lateral" in serialized


def test_client_cannot_supply_deterministic_score_or_context() -> None:
    with pytest.raises(ValidationError):
        CopilotExplainRequest.model_validate(
            {
                "finding_id": "finding-a",
                "deterministic_score": 100,
                "deterministic_tier": "critical",
            }
        )

    with pytest.raises(ValidationError):
        CopilotExplainRequest.model_validate(
            {
                "analysis_id": "analysis-a",
                "path_id": "path-a",
                "asset_ids": ["asset-other"],
            }
        )


def api_config(tmp_path: Path, name: str) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / f'{name}.db'}",
        audit_log_path=str(tmp_path / f"{name}.jsonl"),
        auth_bootstrap_token=f"{name}-token",
        ai_features_enabled=False,
    )


def bootstrap(client: TestClient, config: Settings, *, slug: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": config.auth_bootstrap_token,
            "tenant_slug": slug,
            "tenant_name": f"{slug} Tenant",
            "username": f"{slug}-admin",
            "password": f"{slug}-password",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_finding_source_is_server_resolved_and_score_tampering_is_rejected(tmp_path: Path) -> None:
    config = api_config(tmp_path, "finding-source")
    client = TestClient(create_app(config))
    headers = bootstrap(client, config, slug="finding-source")
    tenant_id = client.get("/api/v1/auth/me", headers=headers).json()["tenant_id"]
    session_factory = create_session_factory(config.database_url)
    with session_factory() as session:
        session.add(
            Finding(
                id="finding-server",
                tenant_id=tenant_id,
                title="Modeled low finding",
                description="Server-side finding description",
                severity="low",
                technique_id="T1059",
                cvss_score=1.0,
                evidence={"evidence_ids": ["evidence-server"]},
                created_at=datetime.now(timezone.utc),
            )
        )
        session.add(
            EvidenceItem(
                id="evidence-server",
                tenant_id=tenant_id,
                evidence_type="fixture",
                source="authorized-fixture",
                title="Reviewed evidence",
                sha256="0" * 64,
                technique_id="T1059",
                review_status="accepted",
                notes="bounded metadata",
                created_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

    response = client.post(
        "/api/v1/risk/ai-assess",
        json={"finding_id": "finding-server"},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["deterministic_score"] == 25.0
    assert response.json()["deterministic_tier"] == "low"

    tampered = client.post(
        "/api/v1/risk/ai-assess",
        json={
            "finding_id": "finding-server",
            "deterministic_score": 100,
            "deterministic_tier": "critical",
        },
        headers=headers,
    )
    assert tampered.status_code == 422


def test_cross_tenant_and_nonexistent_sources_return_safe_not_found(tmp_path: Path) -> None:
    config = api_config(tmp_path, "source-boundary")
    client = TestClient(create_app(config))
    headers = bootstrap(client, config, slug="source-boundary")
    session_factory = create_session_factory(config.database_url)
    with session_factory() as session:
        session.add(
            Finding(
                id="finding-other",
                tenant_id="tenant-other",
                title="Other tenant finding",
                description="Should not resolve",
                severity="critical",
                evidence={},
                created_at=datetime.now(timezone.utc),
            )
        )
        session.add(
            AttackPathAnalysis(
                id="analysis-other",
                tenant_id="tenant-other",
                actor_id="other-user",
                graph_fingerprint="f" * 64,
                summary_json={"paths": [{"path_id": "path-other", "risk_score": 95}]},
                created_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

    for payload in (
        {"finding_id": "finding-other"},
        {"finding_id": "finding-missing"},
        {"analysis_id": "analysis-other", "path_id": "path-other"},
        {"analysis_id": "analysis-missing", "path_id": "path-missing"},
    ):
        response = client.post("/api/v1/risk/ai-assess", json=payload, headers=headers)
        assert response.status_code == 404
        assert response.json()["detail"] == "Resource not found"


def test_registered_path_source_uses_server_score_not_client_context(tmp_path: Path) -> None:
    config = api_config(tmp_path, "path-source")
    client = TestClient(create_app(config))
    headers = bootstrap(client, config, slug="path-source")
    tenant_id = client.get("/api/v1/auth/me", headers=headers).json()["tenant_id"]
    session_factory = create_session_factory(config.database_url)
    with session_factory() as session:
        session.add(
            AttackPathAnalysis(
                id="analysis-server",
                tenant_id=tenant_id,
                actor_id="server-user",
                graph_fingerprint="a" * 64,
                summary_json={
                    "paths": [
                        {
                            "path_id": "path-server",
                            "risk_score": 25.0,
                            "centrality": 0.1,
                            "asset_ids": [],
                            "evidence_ids": [],
                            "technique_ids": ["T1059"],
                            "rationale": "server-derived modeled path",
                        }
                    ]
                },
                created_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

    response = client.post(
        "/api/v1/risk/ai-assess",
        json={"analysis_id": "analysis-server", "path_id": "path-server"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["deterministic_score"] == 25.0
    assert response.json()["deterministic_tier"] == "low"
