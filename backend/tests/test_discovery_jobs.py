from __future__ import annotations

import time
from pathlib import Path

from app.api.routes import build_router
from app.core.audit import AuditLogger
from app.core.config import Settings
from app.core.scope import ScopePolicy
from app.db.models import create_session_factory
from app.schemas.contracts import AssetObservation, ReconResult
from app.services.discovery_jobs import (
    DiscoveryJobNotFound,
    DiscoveryJobService,
    DiscoveryRateLimitExceeded,
)
from app.services.recon import ReconService
from fastapi import FastAPI
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

    def fake_run(targets: list[str], profile: str, dry_run: bool) -> ReconResult:
        return ReconResult(
            scan_id="scan-ai03-fixture",
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
        assert completed.scan_id == "scan-ai03-fixture"

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


def test_discovery_api_is_fail_closed_and_enforces_scope(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        audit_log_path=str(tmp_path / "api-audit.jsonl"),
        allowed_cidrs="192.168.56.0/24",
        discovery_api_token="test-token",
        discovery_tenant_id="tenant-a",
        dry_run=True,
    )
    app = FastAPI()
    app.include_router(build_router(settings))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token", "X-RedPath-Tenant": "tenant-a"}

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

    wrong_tenant = client.get(
        f"/api/v1/discovery/jobs/{job_id}",
        headers={"Authorization": "Bearer test-token", "X-RedPath-Tenant": "tenant-b"},
    )
    assert wrong_tenant.status_code == 403
