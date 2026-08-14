from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from app.core.audit import AuditLogger
from app.core.scope import ScopePolicy
from app.db.models import Asset, DiscoveryJob, ScanRun, create_session_factory, utcnow
from app.schemas.contracts import AssetObservation, ReconResult
from app.services.discovery_jobs import DiscoveryJobService, DiscoveryLeaseLost
from app.services.recon import ReconService
from sqlalchemy import inspect


def wait_for_terminal(service: DiscoveryJobService, tenant_id: str, job_id: str):
    for _ in range(200):
        status = service.get(tenant_id, job_id)
        if status.status in {"completed", "failed"}:
            return status
    raise AssertionError("discovery job did not reach a terminal state")


def test_tenant_lease_and_checkpoint_are_owner_bound_and_bounded(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'lease.db'}")
    audit = AuditLogger(str(tmp_path / "lease-audit.jsonl"))
    service = DiscoveryJobService(
        ReconService(ScopePolicy.from_strings(["192.168.56.0/24"])),
        session_factory,
        audit,
        checkpoint_max_bytes=256,
    )
    try:
        with session_factory() as session:
            session.add(
                DiscoveryJob(
                    id="lease-job",
                    tenant_id="tenant-a",
                    actor="alice",
                    status="queued",
                    dry_run=True,
                    targets=["192.168.56.10"],
                    created_at=utcnow(),
                )
            )
            session.commit()

        lease = service._acquire_lease("lease-job", "worker-a")
        assert lease[0] == "tenant-a"
        assert service.checkpoint("lease-job", "worker-a", "observing", {"payload": "x" * 500}) is True
        assert service.checkpoint("lease-job", "worker-b", "forged", {}) is False
        with pytest.raises(DiscoveryLeaseLost):
            service._acquire_lease("lease-job", "worker-b")
        with session_factory() as session:
            stored = session.get(DiscoveryJob, "lease-job")
            assert stored is not None
            stored.lease_expires_at = utcnow() - timedelta(seconds=1)
            session.commit()
        reclaimed = service._acquire_lease("lease-job", "worker-b")
        assert reclaimed[0] == "tenant-a"
        with session_factory() as session:
            stored = session.get(DiscoveryJob, "lease-job")
            assert stored is not None
            assert stored.lease_owner == "worker-b"
            assert stored.recovery_count == 1
            assert stored.checkpoint_json["stage"] == "lease_reclaimed"
            assert len(json.dumps(stored.checkpoint_json).encode("utf-8")) <= 256
        assert "discovery.job_lease_recovered" in (tmp_path / "lease-audit.jsonl").read_text()
    finally:
        service.shutdown()


def test_transient_retry_budget_and_result_compaction(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'retry.db'}")
    audit = AuditLogger(str(tmp_path / "retry-audit.jsonl"))
    recon = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))
    calls = {"count": 0}

    def fake_run(targets: list[str], profile: str, dry_run: bool, *, scan_id: str | None = None) -> ReconResult:
        calls["count"] += 1
        if calls["count"] == 1:
            raise TimeoutError("fixture timeout")
        return ReconResult(
            scan_id=scan_id or "retry-scan",
            dry_run=dry_run,
            targets=targets,
            commands=[],
            warnings=["warning-" + ("x" * 300)] * 100,
            assets=[
                AssetObservation(
                    ip=f"192.168.56.{index}",
                    hostname="host-" + ("x" * 240),
                    ports=[443],
                    services=["https"],
                )
                for index in range(1, 65)
            ],
        )

    recon.run = fake_run  # type: ignore[method-assign]
    service = DiscoveryJobService(
        recon,
        session_factory,
        audit,
        max_workers=1,
        retry_budget=1,
        result_max_bytes=1024,
    )
    try:
        queued = service.submit("tenant-a", ["192.168.56.10"], "safe", True, actor="alice")
        failed = wait_for_terminal(service, "tenant-a", queued.job_id)
        assert failed.status == "failed"
        assert failed.retry_class == "transient"
        assert failed.attempt_count == 1
        assert failed.next_retry_at is not None
        with session_factory() as session:
            job = session.get(DiscoveryJob, queued.job_id)
            assert job is not None
            job.next_retry_at = utcnow() - timedelta(seconds=1)
            session.commit()

        retried = service.retry_failed("tenant-a", queued.job_id, actor="alice")
        assert retried.status in {"queued", "running", "completed"}
        completed = wait_for_terminal(service, "tenant-a", queued.job_id)
        assert completed.status == "completed"
        assert completed.attempt_count == 2
        assert completed.result_compacted is True
        assert completed.result_bytes is not None and completed.result_bytes <= 1024
        assert completed.result is not None and completed.result.get("commands_omitted") is True
        assert calls["count"] == 2
    finally:
        service.shutdown()


def test_inventory_page_fixture_uses_composite_indexes_and_bounded_page(tmp_path: Path) -> None:
    session_factory = create_session_factory(f"sqlite:///{tmp_path / 'inventory-index.db'}")
    audit = AuditLogger(str(tmp_path / "inventory-index-audit.jsonl"))
    service = DiscoveryJobService(
        ReconService(ScopePolicy.from_strings(["192.168.56.0/24"])),
        session_factory,
        audit,
    )
    try:
        with session_factory() as session:
            scan = ScanRun(
                id="index-scan",
                tenant_id="tenant-a",
                mode="safe",
                dry_run=True,
                targets=["192.168.56.0/24"],
                created_at=utcnow(),
            )
            session.add(scan)
            for index in range(1, 121):
                session.add(
                    Asset(
                        id=f"asset-{index}",
                        tenant_id="tenant-a",
                        scan_id=scan.id,
                        ip=f"192.168.56.{index}",
                        hostname=f"inventory-host-{index}",
                        ports=[443],
                        services=["https"],
                        first_seen_at=scan.created_at,
                        last_seen_at=scan.created_at,
                    )
                )
            session.commit()
            indexes = {index["name"] for index in inspect(session.get_bind()).get_indexes("assets")}

        page = service.inventory_page("tenant-a", limit=50, query="inventory-host", service="https")
        assert len(page.items) == 50
        assert page.pagination.has_more is True
        assert page.pagination.next_cursor == "50"
        assert {"ix_assets_tenant_ip", "ix_assets_tenant_last_seen"}.issubset(indexes)
    finally:
        service.shutdown()
