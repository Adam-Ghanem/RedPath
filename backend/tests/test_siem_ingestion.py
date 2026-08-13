from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from app.core.config import Settings
from app.core.observability import MetricsRegistry
from app.db.models import create_session_factory
from app.main import create_app
from app.models.telemetry import TelemetryDetectionRequest, TelemetryQuery
from app.services.detection_framework import DetectionRuleCatalog
from app.services.siem_ingestion import SiemIngestionService, list_telemetry, normalize_wazuh_document
from app.services.telemetry_correlation import evaluate_telemetry, health_diagnostics, project_case_evidence
from app.services.telemetry_resilience import (
    Checkpoint,
    CheckpointCodec,
    TelemetryResilienceStore,
    inspect_schema,
)
from app.services.wazuh import WazuhIndexerClient
from fastapi.testclient import TestClient


class FakeWazuhClient:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = documents
        self.calls: list[dict] = []

    async def search_alerts(self, **kwargs: object) -> list[dict]:
        self.calls.append(kwargs)
        return self.documents


def _query(*, hours: int = 1, tenant_id: str = "lab") -> TelemetryQuery:
    end = datetime(2026, 8, 13, 1, tzinfo=timezone.utc)
    return TelemetryQuery(tenant_id=tenant_id, start=end - timedelta(hours=hours), end=end, limit=50)


def _fixture_document() -> dict:
    return {
        "_id": "alert-001",
        "_source": {
            "timestamp": "2026-08-13T00:30:00Z",
            "rule": {
                "id": "100001",
                "level": 12,
                "description": "T1558.003 suspicious authentication activity",
                "mitre": {"id": ["T1558.003"]},
            },
            "agent": {"id": "007", "name": "dc01"},
            "location": "eventchannel",
            "decoder": {"name": "windows_eventchannel"},
            "data": {
                "event_id": "4769",
                "srcuser": "analyst01",
                "command": "do not copy into the analyst projection",
                "password": "secret",
            },
        },
    }


def test_normalize_wazuh_document_redacts_arbitrary_raw_fields() -> None:
    event = normalize_wazuh_document(_fixture_document(), "lab")

    assert event.tenant_id == "lab"
    assert event.severity == "high"
    assert event.rule_id == "100001"
    assert event.technique_ids == ["T1558.003"]
    assert event.asset_id == "wazuh-agent:007"
    assert event.safe_fields == {
        "agent_id": "007",
        "agent_name": "dc01",
        "location": "eventchannel",
        "decoder": "windows_eventchannel",
    }
    assert "command" not in event.model_dump_json()
    assert "password" not in event.model_dump_json()
    assert len(event.raw_sha256) == 64


def test_ingest_is_tenant_scoped_and_idempotent(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'telemetry.db'}")
    client = FakeWazuhClient([_fixture_document()])
    service = SiemIngestionService(client, session_factory, max_query_window_hours=24)

    first = asyncio.run(service.ingest(_query()))
    second = asyncio.run(service.ingest(_query()))

    assert first.fetched_count == 1
    assert first.stored_count == 1
    assert first.deduplicated_count == 0
    assert second.stored_count == 0
    assert second.deduplicated_count == 1
    listed = list_telemetry(
        session_factory,
        tenant_id="lab",
        start=_query().start,
        end=_query().end,
        limit=10,
    )
    assert len(listed.events) == 1
    assert listed.events[0].tenant_id == "lab"
    assert len(client.calls) == 2


def test_ingest_rejects_query_window_over_limit(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'telemetry.db'}")
    service = SiemIngestionService(FakeWazuhClient([]), session_factory, max_query_window_hours=24)

    with pytest.raises(ValueError, match="cannot exceed"):
        asyncio.run(service.ingest(_query(hours=25)))


def test_protected_api_ingest_and_readback(tmp_path, monkeypatch) -> None:
    async def fake_search_alerts(self, **kwargs: object) -> list[dict]:
        return [_fixture_document()]

    monkeypatch.setattr("app.services.wazuh.WazuhIndexerClient.search_alerts", fake_search_alerts)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        audit_log_path=str(tmp_path / "audit.jsonl"),
        auth_bootstrap_token="siem-test-bootstrap-token",
    )

    with TestClient(create_app(settings)) as client:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": settings.auth_bootstrap_token,
                "tenant_slug": "siem",
                "tenant_name": "SIEM Test Tenant",
                "username": "siem-admin",
                "password": "siem-admin-password",
            },
        )
        assert bootstrap.status_code == 201
        headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200
        query = {
            "tenant_id": me.json()["tenant_id"],
            "start": "2026-08-13T00:00:00Z",
            "end": "2026-08-13T01:00:00Z",
            "limit": 10,
        }
        assert client.post("/api/v1/siem/telemetry/ingest", json=query).status_code == 401
        response = client.post("/api/v1/siem/telemetry/ingest", json=query, headers=headers)
        assert response.status_code == 200
        assert response.json()["stored_count"] == 1
        assert "data" not in response.text
        unauthorized_tenant = client.post(
            "/api/v1/siem/telemetry/ingest",
            json={**query, "tenant_id": "other-tenant"},
            headers=headers,
        )
        assert unauthorized_tenant.status_code == 403
        readback = client.get(
            "/api/v1/siem/telemetry",
            params={"start": query["start"], "end": query["end"]},
            headers=headers,
        )
        assert readback.status_code == 200
        assert len(readback.json()["events"]) == 1
        detection = client.post(
            "/api/v1/siem/telemetry/detections/evaluate",
            json={
                "start": query["start"],
                "end": query["end"],
                "rule_ids": ["ad.kerberoasting.service-ticket"],
                "limit": 10,
            },
            headers=headers,
        )
        assert detection.status_code == 200
        assert detection.json()["event_count"] == 1
        assert detection.json()["evaluation"]["matches"][0]["rule_id"] == "ad.kerberoasting.service-ticket"
        evidence = client.get(
            "/api/v1/siem/telemetry/evidence",
            params={"start": query["start"], "end": query["end"], "limit": 10},
            headers=headers,
        )
        assert evidence.status_code == 200
        assert evidence.json()[0]["tenant_id"] == me.json()["tenant_id"]
        assert "password" not in evidence.text
        health = client.get("/api/v1/siem/telemetry/health", headers=headers)
        assert health.status_code == 200
        assert health.json()["status"] == "healthy"
        too_wide = client.post(
            "/api/v1/siem/telemetry/detections/evaluate",
            json={
                "start": "2026-08-11T00:00:00Z",
                "end": query["end"],
                "limit": 10,
            },
            headers=headers,
        )
        assert too_wide.status_code == 422


def test_wazuh_client_builds_read_only_bounded_search(monkeypatch) -> None:
    captured: dict = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"hits": {"hits": [{"_source": {"rule": {"id": "1"}}}]}}

    class FakeAsyncClient:
        def __init__(self, **kwargs: object) -> None:
            captured["client_kwargs"] = kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> FakeResponse:
            captured["url"] = url
            captured["post_kwargs"] = kwargs
            return FakeResponse()

    monkeypatch.setattr("app.services.wazuh.httpx.AsyncClient", FakeAsyncClient)
    client = WazuhIndexerClient("https://wazuh.example:9200", "reader", "secret", timeout_seconds=7)
    start = datetime(2026, 8, 13, tzinfo=timezone.utc)
    alerts = asyncio.run(client.search_alerts(start=start, end=start + timedelta(hours=1), size=5000))

    assert alerts == [{"rule": {"id": "1"}}]
    assert captured["url"] == "https://wazuh.example:9200/wazuh-alerts*/_search"
    assert captured["client_kwargs"]["timeout"] == 7
    assert captured["post_kwargs"]["auth"] == ("reader", "secret")
    body = captured["post_kwargs"]["json"]
    assert body["size"] == 1000
    assert body["query"]["bool"]["must"][0]["range"]["timestamp"]["gte"].endswith("+00:00")
    assert "query_string" not in str(body)
    assert body["sort"][0]["timestamp"]["order"] == "asc"



def test_normalized_event_has_correlation_allowlist_without_sensitive_fields() -> None:
    document = _fixture_document()
    document["_source"]["rule"]["description"] += " Authorization: Bearer secret-value"
    event = normalize_wazuh_document(document, "lab")

    assert event.correlation_fields == {
        "event_id": "4769",
        "srcuser": hashlib.sha256(b"analyst01").hexdigest()[:16],
    }
    assert "secret-value" not in event.summary
    assert "password" not in event.model_dump_json()
    assert "command" not in event.model_dump_json()


def test_telemetry_detection_case_projection_health_and_replay_dedup(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'phase2.db'}")
    service = SiemIngestionService(FakeWazuhClient([_fixture_document()]), session_factory)
    first = asyncio.run(service.ingest(_query()))
    second = asyncio.run(service.ingest(_query()))
    request = TelemetryDetectionRequest(
        start=_query().start,
        end=_query().end,
        rule_ids=["ad.kerberoasting.service-ticket"],
        limit=10,
    )

    evaluation = evaluate_telemetry(
        session_factory,
        tenant_id="lab",
        request=request,
        catalog=DetectionRuleCatalog(),
    )
    listed = list_telemetry(
        session_factory,
        tenant_id="lab",
        start=request.start,
        end=request.end,
        limit=10,
    )
    projections = project_case_evidence(listed.events)
    health = health_diagnostics(session_factory, tenant_id="lab")
    other_tenant = evaluate_telemetry(
        session_factory,
        tenant_id="other",
        request=request,
        catalog=DetectionRuleCatalog(),
    )

    assert first.stored_count == 1
    assert second.stored_count == 0
    assert second.deduplicated_count == 1
    assert evaluation.event_count == 1
    assert evaluation.evaluation["matches"][0]["rule_id"] == "ad.kerberoasting.service-ticket"
    assert len(projections) == 1
    assert projections[0].event_id == listed.events[0].event_id
    assert projections[0].raw_sha256 == listed.events[0].raw_sha256
    assert health.status == "healthy"
    assert health.total_runs == 2
    assert health.total_events == 1
    assert health.total_deduplicated == 1
    assert other_tenant.event_count == 0


class PagingWazuhClient(FakeWazuhClient):
    def __init__(self, documents: list[dict]) -> None:
        super().__init__(documents)
        self.page_cursors: list[str | None] = []

    async def search_alerts_page(self, **kwargs: object) -> tuple[list[dict], str | None]:
        cursor = kwargs.get("checkpoint_cursor")
        self.page_cursors.append(cursor if isinstance(cursor, str) else None)
        return self.documents, CheckpointCodec.encode(
            Checkpoint(datetime(2026, 8, 13, 0, 30, tzinfo=timezone.utc), "alert-001")
        )


def test_checkpoint_round_trip_and_recovery_after_restart(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'recovery.db'}")
    resilience = TelemetryResilienceStore(session_factory)
    cursor = CheckpointCodec.encode(
        Checkpoint(datetime(2026, 8, 13, 0, 30, tzinfo=timezone.utc), "alert-001")
    )
    assert CheckpointCodec.decode(cursor).provider_id == "alert-001"
    client = PagingWazuhClient([_fixture_document()])
    service = SiemIngestionService(client, session_factory, resilience=resilience)

    asyncio.run(service.ingest(_query()))
    asyncio.run(service.ingest(_query()))

    assert client.page_cursors == [None, cursor]
    assert resilience.get_checkpoint("lab") == cursor
    assert resilience.health(tenant_id="lab").checkpoint_present is True


def test_schema_drift_fails_closed_and_dead_letter_metadata_is_bounded(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'drift.db'}")
    resilience = TelemetryResilienceStore(session_factory, dead_letter_max_metadata_bytes=256)
    malformed = {"_id": "drift-1", "_source": {"timestamp": "2026-08-13T00:30:00Z"}}
    service = SiemIngestionService(FakeWazuhClient([malformed]), session_factory, resilience=resilience)

    with pytest.raises(ValueError, match="schema drift"):
        asyncio.run(service.ingest(_query()))

    health = resilience.health(tenant_id="lab")
    assert health.status == "degraded"
    assert health.schema_drift_count == 1
    assert health.dead_letter_count == 1
    with session_factory() as session:
        from app.db.models import TelemetryDeadLetter

        dead_letter = session.query(TelemetryDeadLetter).one()
        assert len(str(dead_letter.metadata_json).encode("utf-8")) <= 256
        assert dead_letter.error_code == "schema_drift"


def test_dead_letter_retention_is_tenant_scoped_and_metrics_are_fixed_name(tmp_path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'retention.db'}")
    metrics = MetricsRegistry()
    resilience = TelemetryResilienceStore(session_factory, metrics=metrics)
    resilience.record_failure(tenant_id="lab", error_code="connector_error")
    resilience.record_failure(tenant_id="other", error_code="connector_error")
    with session_factory() as session:
        from app.db.models import TelemetryDeadLetter

        for row in session.query(TelemetryDeadLetter).all():
            row.expires_at = (
                datetime(2026, 8, 12, tzinfo=timezone.utc)
                if row.tenant_id == "lab"
                else datetime(2026, 8, 14, tzinfo=timezone.utc)
            )
        session.commit()

    assert resilience.prune_dead_letters(
        tenant_id="lab", now=datetime(2026, 8, 13, tzinfo=timezone.utc)
    ) == 1
    assert resilience.health(tenant_id="lab").dead_letter_count == 0
    assert resilience.health(tenant_id="other").dead_letter_count == 1
    output = metrics.prometheus()
    assert "redpath_telemetry_dead_letters_total 2" in output
    assert "tenant_id" not in output


def test_schema_observation_and_connector_configuration_fail_closed() -> None:
    observation = inspect_schema(_fixture_document())
    drift = inspect_schema({"_source": {"timestamp": "2026-08-13T00:30:00Z"}})

    assert observation.schema_version == "wazuh-alert-v1"
    assert observation.drift_reason is None
    assert drift.drift_reason == "missing_rule_object"
    with pytest.raises(ValueError, match="HTTPS"):
        WazuhIndexerClient.validate_configuration(
            base_url="http://wazuh.example:9200",
            username="reader",
            password="secret",
            verify_tls=True,
            timeout_seconds=20,
        )
    with pytest.raises(ValueError, match="read-only"):
        WazuhIndexerClient.validate_configuration(
            base_url="https://wazuh.example:9200",
            username="reader",
            password="secret",
            verify_tls=True,
            timeout_seconds=20,
            read_only=False,
        )
