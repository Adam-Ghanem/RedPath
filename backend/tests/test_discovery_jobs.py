from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from app.core.audit import AuditLogger
from app.core.config import Settings
from app.core.scope import ScopePolicy
from app.db.models import Asset, DiscoveryJob, ScanRun, create_session_factory, utcnow
from app.main import create_app
from app.models.domain import Asset as SharedAsset
from app.schemas.contracts import AssetObservation, ReconResult
from app.services.discovery_jobs import (
    DiscoveryJobNotFound,
    DiscoveryJobService,
    DiscoveryRateLimitExceeded,
)
from app.services.recon import ReconService
from fastapi.testclient import TestClient


def wait_for_completion(service: DiscoveryJobService, tenant_id: str, job_id: str):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status = service.get(tenant_id, job_id)
        if status.status in {"completed", "failed"}:
            return status
        time.sleep(0.02)
    raise AssertionError("discovery job did not complete within 3 seconds")


def test_discovery_worker_persists_inventory_and_enforces_tenant_isolation(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'discovery.db'}"
    session_factory = create_session_factory(database_url)
    audit = AuditLogger(str(tmp_path / "audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))

    def fake_run(
        targets: list[str],
        profile: str,
        dry_run: bool,
        *,
        scan_id: str | None = None,
    ) -> ReconResult:
        return ReconResult(
            scan_id=scan_id or "scan-ai03-fixture",
            dry_run=dry_run,
            targets=targets,
            commands=[],
            assets=[
                AssetObservation(
                    ip=targets[0],
                    hostname="authorized-host",
                    ports=[443, 443, 22],
                    services=["https", "https", "ssh"],
                )
            ],
        )

    recon.run = fake_run  # type: ignore[method-assign]
    service = DiscoveryJobService(recon, session_factory, audit, max_workers=1, max_jobs_per_minute=1)
    try:
        queued = service.submit("tenant-a", ["192.168.56.10"], "safe", False)
        try:
            service.submit("tenant-a", ["192.168.56.11"], "safe", False)
        except DiscoveryRateLimitExceeded:
            pass
        else:
            raise AssertionError("discovery submission rate limit was not enforced")
        assert queued.status in {"queued", "running", "completed"}
        completed = wait_for_completion(service, "tenant-a", queued.job_id)
        assert completed.status == "completed"
        assert completed.progress_percent == 100
        assert completed.duration_ms is not None
        assert completed.scan_id == service._scan_id(queued.job_id)
        with session_factory() as session:
            scan = session.get(ScanRun, completed.scan_id)
            persisted_assets = session.query(Asset).filter_by(scan_id=completed.scan_id).all()
        assert scan is not None and scan.tenant_id == "tenant-a"
        assert persisted_assets and all(asset.tenant_id == "tenant-a" for asset in persisted_assets)

        assets = service.inventory("tenant-a")
        assert len(assets) == 1
        assert assets[0].schema_version == "1.0"
        assert assets[0].tenant_id == "tenant-a"
        assert assets[0].ports == [22, 443]
        assert assets[0].services == ["https", "ssh"]

        try:
            service.get("tenant-b", queued.job_id)
        except DiscoveryJobNotFound:
            pass
        else:
            raise AssertionError("cross-tenant job access was accepted")
        assert service.inventory("tenant-b") == []
    finally:
        service.shutdown()


def test_reconciliation_is_idempotent_and_preserves_provenance(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'reconcile.db'}")
    audit = AuditLogger(str(tmp_path / "reconcile-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))

    def fake_run(
        targets: list[str],
        profile: str,
        dry_run: bool,
        *,
        scan_id: str | None = None,
    ) -> ReconResult:
        return ReconResult(
            scan_id=scan_id or "fixture-scan",
            dry_run=dry_run,
            targets=targets,
            commands=[],
            assets=[
                AssetObservation(
                    ip=targets[0],
                    hostname="reconciled-host",
                    ports=[443, 22, 443],
                    services=["https", "ssh", "https"],
                    source="fixture",
                )
            ],
        )

    recon.run = fake_run  # type: ignore[method-assign]
    service = DiscoveryJobService(recon, session_factory, audit, max_workers=1, max_jobs_per_minute=10)
    try:
        first = service.submit("tenant-a", ["192.168.56.10"], "safe", False, actor="alice")
        wait_for_completion(service, "tenant-a", first.job_id)
        first_inventory = service.inventory("tenant-a", actor="alice")
        first_hash = first_inventory[0].provenance.observation_hash
        second = service.submit("tenant-a", ["192.168.56.10"], "safe", False, actor="alice")
        completed_second = wait_for_completion(service, "tenant-a", second.job_id)

        inventory = service.inventory("tenant-a", actor="alice")
        assert len(inventory) == 1
        item = inventory[0]
        assert item.asset == SharedAsset(
            asset_id=item.asset_id,
            tenant_id="tenant-a",
            display_name="reconciled-host",
            asset_type="host",
        )
        assert item.ports == [22, 443]
        assert item.services == ["https", "ssh"]
        assert item.provenance.actor == "alice"
        assert item.provenance.job_id == second.job_id
        assert item.provenance.scan_id == completed_second.scan_id
        assert item.provenance.observation_hash == first_hash
        assert item.first_seen_at <= item.last_seen_at

        with session_factory() as session:
            assert session.query(Asset).filter_by(tenant_id="tenant-a").count() == 1
            assert session.query(ScanRun).filter_by(tenant_id="tenant-a").count() == 2
            stored = session.get(Asset, item.asset_id)
            assert stored is not None
            assert stored.provenance_json["actor"] == "alice"
            assert stored.observation_hash == item.provenance.observation_hash
    finally:
        service.shutdown()


def test_retention_is_bounded_per_tenant_and_does_not_cross_tenants(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'retention.db'}")
    audit = AuditLogger(str(tmp_path / "retention-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))

    def fake_run(targets: list[str], profile: str, dry_run: bool, *, scan_id: str | None = None) -> ReconResult:
        return ReconResult(
            scan_id=scan_id or "retention-scan",
            dry_run=dry_run,
            targets=targets,
            commands=[],
            assets=[],
        )

    recon.run = fake_run  # type: ignore[method-assign]
    service = DiscoveryJobService(
        recon,
        session_factory,
        audit,
        max_workers=1,
        max_jobs_per_minute=10,
        retention_max=2,
    )
    try:
        tenant_a_jobs = [
            service.submit("tenant-a", [f"192.168.56.{index}"], "safe", True)
            for index in (10, 11, 12)
        ]
        for job in tenant_a_jobs:
            wait_for_completion(service, "tenant-a", job.job_id)
        tenant_b_job = service.submit("tenant-b", ["192.168.56.20"], "safe", True)
        wait_for_completion(service, "tenant-b", tenant_b_job.job_id)

        assert len(service.list("tenant-a")) == 2
        assert len(service.list("tenant-b")) == 1
        with session_factory() as session:
            assert session.query(DiscoveryJob).filter_by(tenant_id="tenant-a").count() == 2
            assert session.query(DiscoveryJob).filter_by(tenant_id="tenant-b").count() == 1
    finally:
        service.shutdown()


def test_inventory_requires_matching_asset_and_scan_tenant(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'tenant-mismatch.db'}")
    audit = AuditLogger(str(tmp_path / "tenant-mismatch-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))
    service = DiscoveryJobService(recon, session_factory, audit, max_workers=1)
    try:
        with session_factory() as session:
            scan = ScanRun(
                id="scan-tenant-a",
                tenant_id="tenant-a",
                mode="safe",
                dry_run=True,
                targets=["192.168.56.10"],
                created_at=utcnow(),
            )
            session.add(scan)
            session.add(
                Asset(
                    id="asset-tenant-b",
                    tenant_id="tenant-b",
                    scan_id=scan.id,
                    ip="192.168.56.10",
                    ports=[22],
                    services=["ssh"],
                    first_seen_at=scan.created_at,
                    last_seen_at=scan.created_at,
                )
            )
            session.commit()
        assert service.inventory("tenant-a") == []
    finally:
        service.shutdown()


def test_inventory_page_filters_paginates_and_stays_tenant_scoped(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'inventory-page.db'}")
    audit = AuditLogger(str(tmp_path / "inventory-page-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))

    def fake_run(targets: list[str], profile: str, dry_run: bool, *, scan_id: str | None = None) -> ReconResult:
        target = targets[0]
        last_octet = int(target.rsplit(".", 1)[1])
        service_name = "ssh" if last_octet % 2 else "https"
        return ReconResult(
            scan_id=scan_id or "page-scan",
            dry_run=dry_run,
            targets=targets,
            commands=[],
            assets=[
                AssetObservation(
                    ip=target,
                    hostname=f"authorized-host-{last_octet}",
                    ports=[22 if service_name == "ssh" else 443],
                    services=[service_name],
                )
            ],
        )

    recon.run = fake_run  # type: ignore[method-assign]
    service = DiscoveryJobService(recon, session_factory, audit, max_workers=1, max_jobs_per_minute=10)
    try:
        tenant_a_jobs = [
            service.submit("tenant-a", [f"192.168.56.{octet}"], "safe", False, actor="alice")
            for octet in (10, 11, 12)
        ]
        for job in tenant_a_jobs:
            wait_for_completion(service, "tenant-a", job.job_id)
        tenant_b_job = service.submit("tenant-b", ["192.168.56.20"], "safe", False, actor="bob")
        wait_for_completion(service, "tenant-b", tenant_b_job.job_id)

        first = service.inventory_page("tenant-a", limit=2, actor="alice")
        assert len(first.items) == 2
        assert first.pagination.has_more is True
        assert first.pagination.next_cursor == "2"
        assert all(item.tenant_id == "tenant-a" for item in first.items)

        second = service.inventory_page(
            "tenant-a",
            limit=2,
            cursor=first.pagination.next_cursor,
            actor="alice",
        )
        assert len(second.items) == 1
        assert second.pagination.has_more is False
        assert service.inventory_page("tenant-b", limit=10).items[0].tenant_id == "tenant-b"
        assert len(service.inventory_page("tenant-a", query="host-12").items) == 1
        assert len(service.inventory_page("tenant-a", service="ssh").items) == 1
        assert len(service.inventory_page("tenant-a", port=443).items) == 2
    finally:
        service.shutdown()


def test_stale_recovery_fails_inflight_job_without_retrying_scan(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'recovery.db'}")
    audit = AuditLogger(str(tmp_path / "recovery-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))
    service = DiscoveryJobService(
        recon,
        session_factory,
        audit,
        max_workers=1,
        recovery_timeout_seconds=30,
    )
    try:
        with session_factory() as session:
            job = DiscoveryJob(
                id="stale-job",
                tenant_id="tenant-a",
                actor="alice",
                status="running",
                dry_run=True,
                targets=["192.168.56.10"],
                started_at=utcnow() - timedelta(seconds=60),
                created_at=utcnow() - timedelta(seconds=60),
            )
            session.add(job)
            session.commit()

        assert service.recover_stale_jobs(tenant_id="tenant-a", actor="alice") == 1
        recovered = service.get("tenant-a", "stale-job", actor="alice")
        assert recovered.status == "failed"
        assert recovered.error == "RecoveryTimeout: worker exceeded bounded recovery window"
        assert recovered.recovery_count == 1
        assert recovered.duration_ms is not None
        assert "discovery.jobs_recovered" in (tmp_path / "recovery-audit.jsonl").read_text()
        with session_factory() as session:
            assert session.query(ScanRun).count() == 0
            assert session.query(Asset).count() == 0
    finally:
        service.shutdown()


def test_retention_cleanup_removes_only_expired_terminal_jobs(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'cleanup.db'}")
    audit = AuditLogger(str(tmp_path / "cleanup-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))
    service = DiscoveryJobService(recon, session_factory, audit, max_workers=1)
    try:
        with session_factory() as session:
            session.add(
                DiscoveryJob(
                    id="expired-job",
                    tenant_id="tenant-a",
                    actor="alice",
                    status="completed",
                    dry_run=True,
                    targets=["192.168.56.10"],
                    created_at=utcnow() - timedelta(hours=2),
                    completed_at=utcnow() - timedelta(hours=2),
                    expires_at=utcnow() - timedelta(hours=1),
                )
            )
            session.add(
                DiscoveryJob(
                    id="active-job",
                    tenant_id="tenant-a",
                    actor="alice",
                    status="running",
                    dry_run=True,
                    targets=["192.168.56.11"],
                    created_at=utcnow() - timedelta(hours=2),
                    started_at=utcnow() - timedelta(hours=2),
                    expires_at=utcnow() - timedelta(hours=1),
                )
            )
            session.commit()

        assert service.cleanup_retention("tenant-a", actor="alice") == 1
        with session_factory() as session:
            assert session.get(DiscoveryJob, "expired-job") is None
            assert session.get(DiscoveryJob, "active-job") is not None
    finally:
        service.shutdown()


def test_discovery_api_is_fail_closed_and_enforces_scope(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        audit_log_path=str(tmp_path / "api-audit.jsonl"),
        allowed_cidrs="192.168.56.0/24",
        auth_bootstrap_token="discovery-test-bootstrap-token",
        dry_run=True,
    )
    client = TestClient(create_app(settings))
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "discovery",
            "tenant_name": "Discovery Test Tenant",
            "username": "discovery-admin",
            "password": "discovery-admin-password",
        },
    )
    assert bootstrap.status_code == 201
    headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}

    unauthenticated = client.get("/api/v1/discovery/jobs")
    assert unauthenticated.status_code == 401

    out_of_scope = client.post(
        "/api/v1/discovery/jobs",
        headers=headers,
        json={"targets": ["8.8.8.8"], "profile": "safe", "dry_run": True},
    )
    assert out_of_scope.status_code == 403

    accepted = client.post(
        "/api/v1/discovery/jobs",
        headers=headers,
        json={"targets": ["192.168.56.10"], "profile": "safe", "dry_run": False},
    )
    assert accepted.status_code == 202
    job_id = accepted.json()["job_id"]

    deadline = time.monotonic() + 3
    status = None
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/discovery/jobs/{job_id}", headers=headers)
        assert response.status_code == 200
        status = response.json()
        if status["status"] in {"completed", "failed"}:
            break
        time.sleep(0.02)
    assert status is not None
    assert status["status"] == "completed"
    assert status["dry_run"] is True
    assert client.get("/api/v1/inventory/assets", headers=headers).json() == []
    page_response = client.get("/api/v1/inventory/assets/page?limit=2&query=authorized", headers=headers)
    assert page_response.status_code == 200
    assert page_response.json()["items"] == []
    assert page_response.json()["pagination"] == {"limit": 2, "next_cursor": None, "has_more": False}
