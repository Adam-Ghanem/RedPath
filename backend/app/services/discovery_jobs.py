from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.audit import AuditLogger
from app.db.models import Asset, DiscoveryJob, ScanRun, utcnow
from app.schemas.contracts import DiscoveryJobStatus, InventoryAsset
from app.services.recon import ReconService


class DiscoveryJobNotFound(KeyError):
    """Raised when a job is absent or belongs to another tenant."""


class DiscoveryRateLimitExceeded(ValueError):
    """Raised when a tenant exceeds the bounded job submission rate."""


class DiscoveryJobService:
    """Queue bounded discovery work and persist only normalized, non-sensitive results."""

    def __init__(
        self,
        recon_service: ReconService,
        session_factory,
        audit: AuditLogger,
        *,
        max_workers: int = 2,
        max_jobs_per_minute: int = 30,
    ) -> None:
        self.recon_service = recon_service
        self.session_factory = session_factory
        self.audit = audit
        self.executor = ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, 4)),
            thread_name_prefix="redpath-discovery",
        )
        self.max_jobs_per_minute = max(1, max_jobs_per_minute)
        self._submission_times: dict[str, deque[float]] = {}
        self._rate_lock = threading.Lock()

    def submit(self, tenant_id: str, targets: list[str], profile: str, dry_run: bool) -> DiscoveryJobStatus:
        normalized_targets = self.recon_service.scope.validate_targets(targets)
        self._check_submission_rate(tenant_id)
        # Planning validates the allow-list and creates only fixed argv lists; it never accepts shell text.
        self.recon_service.plan(normalized_targets, profile)
        job_id = str(uuid.uuid4())
        created_at = utcnow()
        with self.session_factory() as session:
            job = DiscoveryJob(
                id=job_id,
                tenant_id=tenant_id,
                profile=profile,
                status="queued",
                dry_run=dry_run,
                targets=normalized_targets,
                progress_percent=0,
                created_at=created_at,
            )
            session.add(job)
            session.commit()
        self.audit.record(
            "discovery.job_queued",
            {"job_id": job_id, "tenant_id": tenant_id, "target_count": len(normalized_targets), "profile": profile},
            actor="discovery-api",
        )
        self.executor.submit(self._execute, job_id)
        return self.get(tenant_id, job_id)

    def _check_submission_rate(self, tenant_id: str) -> None:
        now = time.monotonic()
        cutoff = now - 60
        with self._rate_lock:
            timestamps = self._submission_times.setdefault(tenant_id, deque())
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if len(timestamps) >= self.max_jobs_per_minute:
                raise DiscoveryRateLimitExceeded("Discovery submission rate limit exceeded")
            timestamps.append(now)

    def _execute(self, job_id: str) -> None:
        with self.session_factory() as session:
            job = session.get(DiscoveryJob, job_id)
            if job is None:
                return
            job.status = "running"
            job.started_at = utcnow()
            job.progress_percent = 10
            session.commit()
            tenant_id = job.tenant_id
            targets = list(job.targets)
            profile = job.profile
            dry_run = job.dry_run

        try:
            result = self.recon_service.run(targets, profile, dry_run)
            with self.session_factory() as session:
                scan = ScanRun(
                    id=result.scan_id,
                    mode=profile,
                    dry_run=result.dry_run,
                    targets=result.targets,
                    warnings=result.warnings,
                    created_at=utcnow(),
                )
                session.add(scan)
                for observation in result.assets:
                    asset_id = self._asset_id(tenant_id, observation.ip)
                    asset = session.get(Asset, asset_id)
                    if asset is None:
                        asset = Asset(id=asset_id, scan_id=result.scan_id, ip=observation.ip)
                        session.add(asset)
                    asset.scan_id = result.scan_id
                    asset.ip = observation.ip
                    asset.hostname = observation.hostname
                    asset.ports = sorted(set(observation.ports))
                    asset.services = sorted(set(observation.services))
                    asset.metadata_json = {"tenant_id": tenant_id, "source": observation.source}

                job = session.get(DiscoveryJob, job_id)
                if job is None:
                    return
                job.status = "completed"
                job.scan_id = result.scan_id
                job.result_json = result.model_dump(mode="json")
                job.progress_percent = 100
                job.completed_at = utcnow()
                session.commit()
            self.audit.record(
                "discovery.job_completed",
                {
                    "job_id": job_id,
                    "tenant_id": tenant_id,
                    "scan_id": result.scan_id,
                    "asset_count": len(result.assets),
                },
                actor="discovery-worker",
            )
        except Exception as exc:  # worker failures are persisted and never escape into the executor
            safe_error = f"{type(exc).__name__}: discovery worker failed"
            with self.session_factory() as session:
                job = session.get(DiscoveryJob, job_id)
                if job is not None:
                    job.status = "failed"
                    job.error = safe_error
                    job.progress_percent = 100
                    job.completed_at = utcnow()
                    session.commit()
            self.audit.record(
                "discovery.job_failed",
                {"job_id": job_id, "tenant_id": tenant_id, "error": safe_error},
                actor="discovery-worker",
            )

    def get(self, tenant_id: str, job_id: str) -> DiscoveryJobStatus:
        with self.session_factory() as session:
            job = session.get(DiscoveryJob, job_id)
            if job is None or job.tenant_id != tenant_id:
                raise DiscoveryJobNotFound(job_id)
            return self._to_status(job)

    def list(self, tenant_id: str, limit: int = 20) -> list[DiscoveryJobStatus]:
        bounded_limit = max(1, min(limit, 100))
        with self.session_factory() as session:
            statement = (
                select(DiscoveryJob)
                .where(DiscoveryJob.tenant_id == tenant_id)
                .order_by(DiscoveryJob.created_at.desc())
                .limit(bounded_limit)
            )
            return [self._to_status(job) for job in session.scalars(statement).all()]

    def inventory(self, tenant_id: str, limit: int = 100) -> list[InventoryAsset]:
        bounded_limit = max(1, min(limit, 500))
        with self.session_factory() as session:
            statement = (
                select(Asset, DiscoveryJob)
                .join(DiscoveryJob, DiscoveryJob.scan_id == Asset.scan_id)
                .where(DiscoveryJob.tenant_id == tenant_id)
                .order_by(Asset.ip.asc())
                .limit(bounded_limit)
            )
            rows = session.execute(statement).all()
            return [
                InventoryAsset(
                    asset_id=asset.id,
                    tenant_id=tenant_id,
                    display_name=asset.hostname or asset.ip,
                    ip=asset.ip,
                    hostname=asset.hostname,
                    ports=list(asset.ports or []),
                    services=list(asset.services or []),
                    scan_id=asset.scan_id,
                    source="recon",
                    discovered_at=job.completed_at or job.created_at,
                )
                for asset, job in rows
            ]

    @staticmethod
    def _asset_id(tenant_id: str, ip: str) -> str:
        digest = hashlib.sha256(f"{tenant_id}:{ip}".encode("utf-8")).hexdigest()[:32]
        return f"asset-{digest}"

    @staticmethod
    def _to_status(job: DiscoveryJob) -> DiscoveryJobStatus:
        return DiscoveryJobStatus(
            job_id=job.id,
            tenant_id=job.tenant_id,
            status=job.status,
            profile=job.profile,
            dry_run=job.dry_run,
            targets=list(job.targets or []),
            scan_id=job.scan_id,
            result=job.result_json,
            error=job.error,
            progress_percent=job.progress_percent,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
        )

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)


def utcnow_iso() -> str:
    """Return an ISO timestamp for clients that need a plain string."""
    return datetime.now(timezone.utc).isoformat()
