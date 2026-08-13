from pathlib import Path
from uuid import uuid4

import pytest
from app.core.config import Settings
from app.main import create_app
from app.schemas.contracts import (
    AttackEdge,
    AttackNode,
    AttackPathAnalysisRequest,
    CoverageObservation,
)
from app.services.ai_risk import AIService
from app.services.attack_path_risk import analyze_attack_path_risk
from fastapi.testclient import TestClient


def _path():
    result = analyze_attack_path_risk(
        AttackPathAnalysisRequest(
            tenant_id="tenant-ai",
            nodes=[
                AttackNode(id="entry", label="Entry", kind="asset", is_entry_point=True),
                AttackNode(id="crown", label="Crown", kind="asset", criticality=1.0, is_crown_jewel=True),
            ],
            edges=[
                AttackEdge(
                    source="entry",
                    target="crown",
                    likelihood=8,
                    impact=9,
                    stealth=7,
                    hardening_action="Harden the modeled boundary control.",
                    evidence_ids=["evidence-1"],
                )
            ],
        )
    )
    return result.ranked_paths[0]


def _settings(**overrides) -> Settings:
    values = {
        "ai_features_enabled": True,
        "anthropic_api_key": "test-key",
        "ai_cache_ttl_seconds": 3600,
        "ai_cache_max_entries": 20,
    }
    values.update(overrides)
    return Settings(**values)


def test_ai_risk_success_is_grounded_in_deterministic_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AIService(_settings())
    calls = []

    def fake_provider(*, system: str, user: str) -> dict:
        calls.append((system, user))
        return {
            "explanation": "The path reaches a crown jewel through the supplied edge evidence.",
            "tier": "low",
            "recommended_actions": ["Review the evidence.", "Harden the boundary control."],
            "confidence_note": "Grounded in the supplied path.",
        }

    monkeypatch.setattr(service, "_call_provider", fake_provider)
    result = service.assess_risk(
        _path(),
        centrality_score=0.75,
        detection_observations=[CoverageObservation(technique_id="T1558.003", detected=False)],
    )

    assert calls
    assert result.ai_enhanced is True
    assert result.tier == "critical"
    assert result.centrality_score == 0.75
    assert len(result.recommended_actions) == 2


def test_ai_risk_provider_failure_returns_deterministic_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AIService(_settings())

    def failing_provider(*, system: str, user: str) -> dict:
        raise RuntimeError("simulated outage")

    monkeypatch.setattr(service, "_call_provider", failing_provider)
    result = service.assess_risk(_path(), centrality_score=0.25, detection_observations=[])

    assert result.ai_enhanced is False
    assert result.tier == "critical"
    assert result.centrality_score == 0.25
    assert "deterministic risk engine" in result.confidence_note


def test_ai_disabled_does_not_call_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AIService(_settings(ai_features_enabled=False))
    monkeypatch.setattr(service, "_call_provider", lambda **_: (_ for _ in ()).throw(AssertionError()))

    result = service.assess_risk(_path(), centrality_score=0.5, detection_observations=[])

    assert result.ai_enhanced is False
    assert result.centrality_score == 0.5


def test_copilot_cache_avoids_second_provider_call(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AIService(_settings())
    calls = 0

    def fake_provider(*, system: str, user: str) -> dict:
        nonlocal calls
        calls += 1
        return {
            "explanation": "The stored finding is mapped to the supplied evidence.",
            "evidence_basis": ["Finding severity: high"],
            "confidence_note": "Grounded in stored context.",
        }

    monkeypatch.setattr(service, "_call_provider", fake_provider)
    context = {"title": "Test finding", "severity": "high", "technique_id": "T1558.003"}
    first = service.explain_copilot(
        source_type="finding",
        source_id="finding-1",
        context=context,
        evidence_basis=["Finding severity: high"],
    )
    second = service.explain_copilot(
        source_type="finding",
        source_id="finding-1",
        context=context,
        evidence_basis=["Finding severity: high"],
    )

    assert calls == 1
    assert first.ai_enhanced is True
    assert second.cached is True


def test_copilot_provider_failure_returns_context_only_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AIService(_settings())
    monkeypatch.setattr(service, "_call_provider", lambda **_: (_ for _ in ()).throw(RuntimeError("down")))

    result = service.explain_copilot(
        source_type="finding",
        source_id="finding-1",
        context={"title": "Sensitive finding", "severity": "medium", "technique_id": "T1649"},
        evidence_basis=["Finding severity: medium"],
    )

    assert result.ai_enhanced is False
    assert "Sensitive finding" in result.explanation
    assert "context" in result.confidence_note


def _bootstrap(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "ai-feature-bootstrap-token",
            "tenant_slug": "alpha",
            "tenant_name": "Alpha Security",
            "username": "alpha-admin",
            "password": "alpha-admin-password",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_copilot_has_separate_endpoint_rate_limit(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / f'ai-{uuid4().hex}.db'}",
        audit_log_path=str(tmp_path / f'ai-{uuid4().hex}.jsonl'),
        auth_bootstrap_token="ai-feature-bootstrap-token",
        rate_limit_requests_per_minute=240,
        ai_requests_per_minute=1,
    )
    client = TestClient(create_app(settings))
    headers = _bootstrap(client)

    first = client.post("/api/v1/copilot/explain", headers=headers, json={"finding_id": "missing"})
    second = client.post("/api/v1/copilot/explain", headers=headers, json={"finding_id": "missing"})

    assert first.status_code == 404
    assert second.status_code == 429
