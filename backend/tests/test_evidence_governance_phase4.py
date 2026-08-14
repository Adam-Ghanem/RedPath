from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.db.models import (
    EvidenceItem,
    PcapLifecycle,
    create_session_factory,
    run_alembic_downgrade,
    run_alembic_migrations,
)
from app.main import create_app
from app.services.evidence_governance import MetadataOnlyStorageProvider
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect


def _client(tmp_path: Path) -> tuple[TestClient, Settings, dict[str, str]]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'governance.db'}",
        audit_log_path=str(tmp_path / "governance.jsonl"),
        auth_bootstrap_token="phase4-governance-bootstrap-token",
        rate_limit_requests_per_minute=300,
    )
    client = TestClient(create_app(settings))
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "governance-alpha",
            "tenant_name": "Governance Alpha",
            "username": "phase4-admin",
            "password": "phase4-admin-password",
        },
    )
    assert bootstrap.status_code == 201, bootstrap.text
    return client, settings, {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def _create_case_and_evidence(client: TestClient, headers: dict[str, str]) -> dict:
    case = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "name": "Evidence governance case",
            "objective": "Validate defensive evidence governance boundaries.",
            "scope_snapshot": ["offline-fixture"],
        },
    )
    assert case.status_code == 201, case.text
    evidence = client.post(
        "/api/v1/evidence",
        headers=headers,
        json={
            "campaign_id": case.json()["campaign_id"],
            "evidence_type": "offline_fixture",
            "source": "fixtures/authorized.json",
            "title": "Authorized metadata fixture",
            "sha256": "c" * 64,
            "notes": "token=must-not-appear-in-summary",
        },
    )
    assert evidence.status_code == 201, evidence.text
    return evidence.json()


def _login(client: TestClient, tenant_slug: str, username: str, password: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": tenant_slug, "username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_governance_lifecycle_integrity_privacy_and_dual_control(tmp_path: Path) -> None:
    client, settings, admin_headers = _client(tmp_path)
    evidence = _create_case_and_evidence(client, admin_headers)
    evidence_id = evidence["evidence_id"]

    summary = client.get(f"/api/v1/evidence/{evidence_id}/privacy-summary", headers=admin_headers)
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["manifest_verified"] is True
    assert summary_payload["storage"]["raw_bytes_retained"] is False
    assert summary_payload["storage"]["stored_bytes"] == 0
    assert "must-not-appear-in-summary" not in str(summary_payload)

    integrity = client.post(f"/api/v1/evidence/{evidence_id}/integrity/reverify", headers=admin_headers)
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert integrity.json()["storage_backend"] == "metadata-only"

    held = client.post(
        f"/api/v1/evidence/{evidence_id}/legal-hold",
        headers=admin_headers,
        json={"action": "place", "reason": "Legal review requires preservation."},
    )
    assert held.status_code == 200
    assert held.json()["active"] is True
    assert held.json()["placed_by"] == "phase4-admin"

    retention = client.post(
        f"/api/v1/evidence/{evidence_id}/retention-decision",
        headers=admin_headers,
        json={"decision": "eligible_for_deletion", "reason": "Retention review completed."},
    )
    assert retention.status_code == 201
    assert retention.json()["actor"] == "phase4-admin"
    history = client.get(f"/api/v1/evidence/{evidence_id}/retention-history", headers=admin_headers)
    assert history.status_code == 200
    assert len(history.json()) == 1

    blocked = client.post(
        f"/api/v1/evidence/{evidence_id}/deletion-request",
        headers=admin_headers,
        json={"reason": "Request metadata cleanup after retention review."},
    )
    assert blocked.status_code == 409

    released = client.post(
        f"/api/v1/evidence/{evidence_id}/legal-hold",
        headers=admin_headers,
        json={"action": "release", "reason": "Legal review completed."},
    )
    assert released.status_code == 200
    deletion = client.post(
        f"/api/v1/evidence/{evidence_id}/deletion-request",
        headers=admin_headers,
        json={"reason": "Request metadata cleanup after release."},
    )
    assert deletion.status_code == 201
    request_id = deletion.json()["request_id"]

    same_actor = client.post(
        f"/api/v1/evidence/{evidence_id}/deletion-request/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "note": "Same actor must not approve."},
    )
    assert same_actor.status_code == 409

    created = client.post(
        "/api/v1/auth/users",
        headers=admin_headers,
        json={
            "username": "phase4-approver",
            "password": "phase4-approver-password",
            "roles": ["tenant_admin"],
        },
    )
    assert created.status_code == 201, created.text
    approver_headers = _login(client, "governance-alpha", "phase4-approver", "phase4-approver-password")
    approved = client.post(
        f"/api/v1/evidence/{evidence_id}/deletion-request/{request_id}/decision",
        headers=approver_headers,
        json={"decision": "approve", "note": "Independent approval recorded."},
    )
    assert approved.status_code == 200
    assert approved.json()["state"] == "approved"
    assert approved.json()["decided_by"] == "phase4-approver"

    final_summary = client.get(f"/api/v1/evidence/{evidence_id}/privacy-summary", headers=admin_headers)
    assert final_summary.status_code == 200
    final_payload = final_summary.json()
    assert final_payload["legal_hold"] is False
    assert final_payload["retention_decision"] == "eligible_for_deletion"
    assert final_payload["deletion_request_state"] == "approved"
    assert final_payload["manifest_verified"] is True
    assert "must-not-appear-in-summary" not in str(final_payload)

    audit_lines = [json.loads(line) for line in Path(settings.audit_log_path).read_text().splitlines() if line.strip()]
    assert any(item["operation"] == "evidence.legal_hold_changed" for item in audit_lines)
    assert any(item["operation"] == "evidence.retention_decided" for item in audit_lines)
    assert any(item["operation"] == "evidence.deletion_decided" for item in audit_lines)

    viewer = client.post(
        "/api/v1/auth/users",
        headers=admin_headers,
        json={
            "username": "phase4-viewer",
            "password": "phase4-viewer-password",
            "roles": ["viewer"],
        },
    )
    assert viewer.status_code == 201, viewer.text
    viewer_headers = _login(client, "governance-alpha", "phase4-viewer", "phase4-viewer-password")
    assert client.post(
        f"/api/v1/evidence/{evidence_id}/legal-hold",
        headers=viewer_headers,
        json={"action": "place", "reason": "Viewer must not mutate holds."},
    ).status_code == 403
    assert client.post(
        f"/api/v1/evidence/{evidence_id}/integrity/reverify", headers=viewer_headers
    ).status_code == 403

    tenant = client.post(
        "/api/v1/auth/tenants",
        headers=admin_headers,
        json={
            "slug": "governance-bravo",
            "name": "Governance Bravo",
            "admin_username": "governance-bravo-admin",
            "admin_password": "governance-bravo-password",
        },
    )
    assert tenant.status_code == 201, tenant.text
    bravo_headers = _login(client, "governance-bravo", "governance-bravo-admin", "governance-bravo-password")
    assert client.get(f"/api/v1/evidence/{evidence_id}/privacy-summary", headers=bravo_headers).status_code == 404
    assert client.post(
        f"/api/v1/evidence/{evidence_id}/legal-hold",
        headers=bravo_headers,
        json={"action": "place", "reason": "Cross-tenant hold must fail safely."},
    ).status_code == 404


def test_integrity_reverification_fails_closed_on_manifest_tamper(tmp_path: Path) -> None:
    client, settings, admin_headers = _client(tmp_path)
    evidence = _create_case_and_evidence(client, admin_headers)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        row = session.get(EvidenceItem, evidence["evidence_id"])
        assert row is not None
        row.manifest_sha256 = "0" * 64
        session.commit()
    verification = client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/integrity/reverify",
        headers=admin_headers,
    )
    assert verification.status_code == 200
    assert verification.json()["valid"] is False
    assert verification.json()["failure_code"] == "manifest_mismatch"


def test_legal_hold_synchronizes_pcap_lifecycle(tmp_path: Path) -> None:
    client, settings, admin_headers = _client(tmp_path)
    evidence = _create_case_and_evidence(client, admin_headers)
    session_factory = create_session_factory(settings.database_url)
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        session.add(
            PcapLifecycle(
                id=str(uuid4()),
                tenant_id=evidence["tenant_id"],
                evidence_id=evidence["evidence_id"],
                analysis_id=None,
                state="retained",
                storage_backend="metadata-only",
                storage_locator="none",
                raw_bytes_retained=False,
                stored_bytes=0,
                source_sha256=evidence["sha256"],
                retention_until=now + timedelta(days=30),
                legal_hold=False,
                manifest_sha256=evidence["manifest_sha256"],
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()
    held = client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/legal-hold",
        headers=admin_headers,
        json={"action": "place", "reason": "Preserve the offline capture metadata."},
    )
    assert held.status_code == 200
    with session_factory() as session:
        lifecycle = (
            session.query(PcapLifecycle)
            .filter(PcapLifecycle.evidence_id == evidence["evidence_id"])
            .one()
        )
        assert lifecycle.legal_hold is True


def test_governance_is_tenant_safe_and_storage_provider_fails_closed() -> None:
    provider = MetadataOnlyStorageProvider()
    evidence = EvidenceItem(
        id="evidence-a",
        tenant_id="tenant-a",
        evidence_type="pcap",
        source="offline-upload",
        title="metadata fixture",
        sha256="d" * 64,
    )
    lifecycle = PcapLifecycle(
        id="lifecycle-a",
        tenant_id="tenant-a",
        evidence_id="evidence-a",
        state="retained",
        storage_backend="metadata-only",
        storage_locator="none",
        raw_bytes_retained=False,
        stored_bytes=0,
        source_sha256="d" * 64,
        retention_until=evidence.created_at,
        manifest_sha256="e" * 64,
    )
    assert provider.verify(evidence, lifecycle) == (True, None)
    lifecycle.source_sha256 = "f" * 64
    assert provider.verify(evidence, lifecycle) == (False, "source_hash_mismatch")


def test_phase4_alembic_upgrade_downgrade_reupgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase4-migrations.db'}"
    run_alembic_migrations(database_url)
    engine = create_engine(database_url)
    tables = set(inspect(engine).get_table_names())
    assert {
        "evidence_legal_holds",
        "evidence_retention_decisions",
        "evidence_deletion_requests",
    }.issubset(tables)

    run_alembic_downgrade(database_url, "22d614b2aac8")
    downgraded = set(inspect(engine).get_table_names())
    assert "evidence_legal_holds" not in downgraded
    assert "evidence_retention_decisions" not in downgraded
    assert "evidence_deletion_requests" not in downgraded

    run_alembic_migrations(database_url)
    run_alembic_migrations(database_url)
    upgraded = set(inspect(engine).get_table_names())
    assert {
        "evidence_legal_holds",
        "evidence_retention_decisions",
        "evidence_deletion_requests",
    }.issubset(upgraded)
