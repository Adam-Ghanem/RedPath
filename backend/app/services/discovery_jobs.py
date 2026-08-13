from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, cast, delete, func, or_, select

from app.core.audit import AuditLogger
from app.db.models import Asset, DiscoveryJob, ScanRun, utcnow
from app.kernel.contracts import Page, PaginationMetadata
from app.models.domain import Asset as SharedAsset
from app.schemas.contracts import AssetProvenance, DiscoveryJobStatus, InventoryAsset
from app.services.recon import ReconService


class DiscoveryJobNotFound(KeyError):
    """Raised when a job is absent or belongs to another tenant."""


class DiscoveryRateLimitExceeded(ValueError):
    """Raised when a tenant exceeds the bounded job submission rate."""


class DiscoveryJobService:
    """Queue bounded discovery work and reconcile normalized assets idempotently."""

    def __init__(
        self,
        recon_service: ReconService,
        session_factory,
        audit: AuditLogger,
        *,
        max_workers: int = 2,
        max_jobs_per_minute: int = 30,
        retention_hours: int = 24,
        retention_max: int = 500,
        recovery_timeout_seconds: int = 300,
    ) -> None:
        if retention_hours < 1:
            raise ValueError("retention_hours must be positive")
        if retention_max < 1:
            raise ValueError("retention_max must be positive")
        if recovery_timeout_seconds < 1:
            raise ValueError("recovery_timeout_seconds must be positive")
        self.recon_service = recon_service
        self.session_factory = session_factory
        self.audit = audit
        self.executor = ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, 4)),
            thread_name_prefix="redpath-discovery",
        )
        self.max_jobs_per_minute = max(1, max_jobs_per_minute)
        self.retention_hours = retention_hours
        self.retention_max = retention_max
        self.recovery_timeout_seconds = min(recovery_timeout_seconds, 3600)
        self._submission_times: dict[str, deque[float]] = {}
        self._rate_lock = threading.Lock()

    def submit(
        self,
        tenant_id: str,
        targets: list[str],
        profile: str,
        dry_run: bool,
        *,
        actor: str = "system",
    ) -> DiscoveryJobStatus:
        normalized_targets = self.recon_service.scope.validate_targets(targets)
        self._check_submission_rate(tenant_id)
        self.recover_stale_jobs(tenant_id=tenant_id, actor=actor)
        # Planning validates the allow-list and creates only fixed argv lists; it never accepts shell text.
        self.recon_service.plan(normalized_targets, profile)
        job_id = str(uuid.uuid4())
        created_at = utcnow()
        scan_id = self._scan_id(job_id)
        with self.session_factory() as session:
            job = DiscoveryJob(
                id=job_id,
                tenant_id=tenant_id,
                actor=actor,
                profile=profile,
                status="queued",
                dry_run=dry_run,
                targets=normalized_targets,
                scan_id=scan_id,
                progress_percent=0,
                created_at=created_at,
                expires_at=created_at + timedelta(hours=self.retention_hours),
            )
            session.add(job)
            session.commit()
        pruned_count = self._prune(tenant_id)
        if pruned_count:
            self.audit.record(
                "discovery.jobs_pruned",
                {"tenant_id": tenant_id, "count": pruned_count},
                actor=actor,
            )
        self.audit.record(
            "discovery.job_queued",
            {
                "job_id": job_id,
                "tenant_id": tenant_id,
                "target_count": len(normalized_targets),
                "profile": profile,
                "dry_run": dry_run,
            },
            actor=actor,
        )
        self.executor.submit(self._execute, job_id)
        return self.get(tenant_id, job_id, actor=actor)

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

    def recover_stale_jobs(self, *, tenant_id: str | None = None, actor: str = "system") -> int:
        """Fail bounded stale jobs instead of retrying potentially repeated network actions."""
        cutoff = utcnow() - timedelta(seconds=self.recovery_timeout_seconds)
        recovered_at = utcnow()
        with self.session_factory() as session:
            statement = (
                select(DiscoveryJob)
                .where(
                    DiscoveryJob.status == "running",
                    DiscoveryJob.started_at.is_not(None),
                    DiscoveryJob.started_at < cutoff,
                )
                .order_by(DiscoveryJob.started_at.asc())
                .limit(50)
            )
            if tenant_id is not None:
                statement = statement.where(DiscoveryJob.tenant_id == tenant_id)
            jobs = session.scalars(statement).all()
            for job in jobs:
                job.status = "failed"
                job.error = "RecoveryTimeout: worker exceeded bounded recovery window"
                job.progress_percent = 100
                job.completed_at = recovered_at
                job.recovery_count = (job.recovery_count or 0) + 1
                job.recovered_at = recovered_at
                job.duration_ms = self._duration_ms(job.started_at, recovered_at)
            if jobs:
                session.commit()
        if jobs:
            self.audit.record(
                "discovery.jobs_recovered",
                {
                    "tenant_id": tenant_id,
                    "count": len(jobs),
                    "timeout_seconds": self.recovery_timeout_seconds,
                },
                actor=actor,
            )
        return len(jobs)

    def cleanup_retention(self, tenant_id: str, *, actor: str = "system") -> int:
        """Run bounded terminal-job cleanup; asset rows and audit history are retained."""
        removed = self._prune(tenant_id)
        if removed:
            self.audit.record(
                "discovery.jobs_pruned",
                {"tenant_id": tenant_id, "count": removed},
                actor=actor,
            )
        return removed

    def _execute(self, job_id: str) -> None:
        tenant_id = "unknown"
        actor = "system"
        started_at: datetime | None = None
        with self.session_factory() as session:
            job = session.get(DiscoveryJob, job_id)
            if job is None or job.status in {"completed", "failed", "running"}:
                return
            job.status = "running"
            job.started_at = job.started_at or utcnow()
            started_at = job.started_at
            job.progress_percent = 10

            session.commit()
            tenant_id = job.tenant_id
            actor = job.actor
            targets = list(job.targets)
            profile = job.profile
            dry_run = job.dry_run
            scan_id = job.scan_id or self._scan_id(job.id)
            if job.scan_id is None:
                job.scan_id = scan_id
                session.commit()

        try:
            result = self.recon_service.run(targets, profile, dry_run, scan_id=scan_id)
            completed_at = utcnow()
            with self.session_factory() as session:
                scan = session.get(ScanRun, result.scan_id)
                if scan is None:
                    scan = ScanRun(
                        id=result.scan_id,
                        tenant_id=tenant_id,
                        mode=profile,
                        dry_run=result.dry_run,
                        targets=result.targets,
                        warnings=result.warnings,
                        created_at=completed_at,
                    )
                    session.add(scan)
                elif scan.tenant_id != tenant_id:
                    raise RuntimeError("scan tenant mismatch")

                for observation in self._merge_observations(result.assets):
                    self._reconcile_asset(
                        session,
                        tenant_id=tenant_id,
                        actor=actor,
                        job_id=job_id,
                        scan_id=result.scan_id,
                        dry_run=result.dry_run,
                        observation=observation,
                    observed_at=completed_at,
                )

                job = session.get(DiscoveryJob, job_id)
                if job is None or job.tenant_id != tenant_id:
                    return
                job.status = "completed"
                job.scan_id = result.scan_id
                job.result_json = result.model_dump(mode="json")
                job.progress_percent = 100
                job.completed_at = completed_at
                job.duration_ms = self._duration_ms(started_at, completed_at)
                session.commit()
            pruned_count = self._prune(tenant_id)
            if pruned_count:
                self.audit.record(
                    "discovery.jobs_pruned",
                    {"tenant_id": tenant_id, "count": pruned_count},
                    actor=actor,
                )
            self.audit.record(
                "discovery.job_completed",
                {
                    "job_id": job_id,
                    "tenant_id": tenant_id,
                    "scan_id": result.scan_id,
                    "asset_count": len(result.assets),
                    "dry_run": result.dry_run,
                },
                actor=actor,
            )
        except Exception as exc:  # worker failures are persisted and never escape into the executor
            safe_error = f"{type(exc).__name__}: discovery worker failed"
            with self.session_factory() as session:
                job = session.get(DiscoveryJob, job_id)
                if job is not None:
                    job.status = "failed"
                    job.error = safe_error
                    job.progress_percent = 100
                    completed_at = utcnow()
                    job.completed_at = completed_at
                    job.duration_ms = self._duration_ms(started_at, completed_at)
                    session.commit()
            self.audit.record(
                "discovery.job_failed",
                {"job_id": job_id, "tenant_id": tenant_id, "error": safe_error},
                actor=actor,
            )

    def get(self, tenant_id: str, job_id: str, *, actor: str = "system") -> DiscoveryJobStatus:
        with self.session_factory() as session:
            job = session.get(DiscoveryJob, job_id)
            if (
                job is None
                or job.tenant_id != tenant_id
                or DiscoveryJobService._is_expired(job.expires_at, utcnow())
            ):
                raise DiscoveryJobNotFound(job_id)
            result = self._to_status(job)
        self.audit.record("discovery.job_viewed", {"job_id": job_id, "tenant_id": tenant_id}, actor=actor)
        return result

    def list(self, tenant_id: str, limit: int = 20, *, actor: str = "system") -> list[DiscoveryJobStatus]:
        bounded_limit = max(1, min(limit, 100))
        now = utcnow()
        with self.session_factory() as session:
            statement = (
                select(DiscoveryJob)
                .where(
                    DiscoveryJob.tenant_id == tenant_id,
                    or_(DiscoveryJob.expires_at.is_(None), DiscoveryJob.expires_at >= now),
                )
                .order_by(DiscoveryJob.created_at.desc())
                .limit(bounded_limit)
            )
            result = [self._to_status(job) for job in session.scalars(statement).all()]
        self.audit.record(
            "discovery.jobs_viewed",
            {"tenant_id": tenant_id, "limit": bounded_limit, "result_count": len(result)},
            actor=actor,
        )
        return result

    def inventory(self, tenant_id: str, limit: int = 100, *, actor: str = "system") -> list[InventoryAsset]:
        """Return the legacy list shape for existing clients."""
        bounded_limit = max(1, min(limit, 500))
        with self.session_factory() as session:
            statement = (
                select(Asset, ScanRun)
                .join(ScanRun, ScanRun.id == Asset.scan_id)
                .where(Asset.tenant_id == tenant_id, ScanRun.tenant_id == tenant_id)
                .order_by(Asset.ip.asc())
                .limit(bounded_limit)
            )
            rows = session.execute(statement).all()
            result = [self._to_inventory(asset, scan, tenant_id) for asset, scan in rows]
        self.audit.record(
            "inventory.assets_viewed",
            {"tenant_id": tenant_id, "limit": bounded_limit, "result_count": len(result)},
            actor=actor,
        )
        return result

    def inventory_page(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        cursor: str | None = None,
        query: str | None = None,
        service: str | None = None,
        port: int | None = None,
        actor: str = "system",
    ) -> Page[InventoryAsset]:
        """Return a bounded, tenant-scoped inventory page without external side effects."""
        bounded_limit = max(1, min(limit, 100))
        offset = self._decode_cursor(cursor)
        normalized_query = query.strip()[:128] if query and query.strip() else None
        normalized_service = service.strip().lower()[:64] if service and service.strip() else None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        with self.session_factory() as session:
            predicates = [Asset.tenant_id == tenant_id, ScanRun.tenant_id == tenant_id]
            if normalized_query:
                pattern = f"%{normalized_query}%"
                predicates.append(
                    or_(
                        Asset.ip.ilike(pattern),
                        func.lower(Asset.hostname).ilike(pattern),
                    )
                )
            if normalized_service:
                predicates.append(cast(Asset.services, String).ilike(f"%{normalized_service}%"))
            if port is not None:
                predicates.append(cast(Asset.ports, String).contains(str(port)))
            statement = (
                select(Asset, ScanRun)
                .join(ScanRun, ScanRun.id == Asset.scan_id)
                .where(*predicates)
                .order_by(Asset.ip.asc(), Asset.id.asc())
                .offset(offset)
                .limit(bounded_limit + 1)
            )
            rows = session.execute(statement).all()
            items = [self._to_inventory(asset, scan, tenant_id) for asset, scan in rows[:bounded_limit]]
            if port is not None:
                items = [item for item in items if port in item.ports]
            has_more = len(rows) > bounded_limit

        next_offset = offset + bounded_limit
        next_cursor = str(next_offset) if has_more and next_offset <= 999999 else None
        page = Page[InventoryAsset](
            items=items,
            pagination=PaginationMetadata(
                limit=bounded_limit,
                next_cursor=next_cursor,
                has_more=bool(has_more and next_cursor),
            ),
        )
        filter_hash = hashlib.sha256(
            json.dumps(
                {"query": normalized_query, "service": normalized_service, "port": port},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:16]
        self.audit.record(
            "inventory.assets_viewed",
            {
                "tenant_id": tenant_id,
                "limit": bounded_limit,
                "offset": offset,
                "result_count": len(items),
                "has_more": page.pagination.has_more,
                "filter_hash": filter_hash,
            },
            actor=actor,
        )
        return page

    def _prune(self, tenant_id: str) -> int:
        now = utcnow()
        removed = 0
        with self.session_factory() as session:
            expired_ids = list(
                session.scalars(
                    select(DiscoveryJob.id).where(
                        DiscoveryJob.tenant_id == tenant_id,
                        DiscoveryJob.status.in_(["completed", "failed"]),
                        DiscoveryJob.expires_at.is_not(None),
                        DiscoveryJob.expires_at < now,
                    )
                ).all()
            )
            if expired_ids:
                removed += session.execute(delete(DiscoveryJob).where(DiscoveryJob.id.in_(expired_ids))).rowcount or 0

            retained_ids = list(
                session.scalars(
                    select(DiscoveryJob.id)
                    .where(
                        DiscoveryJob.tenant_id == tenant_id,
                        DiscoveryJob.status.in_(["completed", "failed"]),
                    )
                    .order_by(DiscoveryJob.created_at.desc())
                    .offset(self.retention_max)
                ).all()
            )
            if retained_ids:
                removed += session.execute(delete(DiscoveryJob).where(DiscoveryJob.id.in_(retained_ids))).rowcount or 0
            if removed:
                session.commit()
        return removed

    @staticmethod
    def _reconcile_asset(
        session,
        *,
        tenant_id: str,
        actor: str,
        job_id: str,
        scan_id: str,
        dry_run: bool,
        observation,
        observed_at: datetime,
    ) -> None:
        asset_id = DiscoveryJobService._asset_id(tenant_id, observation.ip)
        observation_hash = DiscoveryJobService._observation_hash(tenant_id, observation)
        shared_asset = SharedAsset(
            asset_id=asset_id,
            tenant_id=tenant_id,
            display_name=observation.hostname or observation.ip,
            asset_type="host",
        )
        provenance = {
            "source": observation.source,
            "scan_id": scan_id,
            "job_id": job_id,
            "actor": actor,
            "observed_at": observed_at.isoformat(),
            "dry_run": dry_run,
            "observation_hash": observation_hash,
        }
        asset = session.get(Asset, shared_asset.asset_id)
        if asset is None:
            asset = Asset(
                id=shared_asset.asset_id,
                tenant_id=shared_asset.tenant_id,
                scan_id=scan_id,
                ip=observation.ip,
                first_seen_at=observed_at,
            )
            session.add(asset)
        elif asset.tenant_id != tenant_id:
            raise RuntimeError("asset tenant mismatch")
        asset.scan_id = scan_id
        asset.ip = observation.ip
        asset.hostname = observation.hostname
        asset.ports = sorted(set(observation.ports))
        asset.services = sorted(set(observation.services))
        asset.metadata_json = {"tenant_id": tenant_id, "source": observation.source}
        asset.provenance_json = provenance
        asset.observation_hash = observation_hash
        asset.first_seen_at = asset.first_seen_at or observed_at
        asset.last_seen_at = observed_at

    @staticmethod
    def _merge_observations(observations):
        merged = {}
        for observation in observations:
            current = merged.get(observation.ip)
            if current is None:
                merged[observation.ip] = observation
                continue
            current.ports = sorted(set(current.ports + observation.ports))
            current.services = sorted(set(current.services + observation.services))
            current.hostname = observation.hostname or current.hostname
        return list(merged.values())

    @staticmethod
    def _asset_id(tenant_id: str, ip: str) -> str:
        digest = hashlib.sha256(f"{tenant_id}:{ip}".encode("utf-8")).hexdigest()[:32]
        return f"asset-{digest}"

    @staticmethod
    def _scan_id(job_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"redpath:discovery:{job_id}"))

    @staticmethod
    def _observation_hash(tenant_id: str, observation) -> str:
        payload = {
            "tenant_id": tenant_id,
            "ip": observation.ip,
            "hostname": observation.hostname,
            "ports": sorted(set(observation.ports)),
            "services": sorted(set(observation.services)),
            "source": observation.source,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    @staticmethod
    def _decode_cursor(cursor: str | None) -> int:
        if cursor is None:
            return 0
        if not cursor.isdigit() or len(cursor) > 6:
            raise ValueError("cursor must be a bounded numeric offset")
        return min(int(cursor), 999999)

    @staticmethod
    def _is_expired(expires_at: datetime | None, now: datetime) -> bool:
        if expires_at is None:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at < now

    @staticmethod
    def _to_inventory(asset: Asset, scan: ScanRun, tenant_id: str) -> InventoryAsset:
        provenance_data = dict(asset.provenance_json or {})
        observed_at = asset.last_seen_at or scan.created_at
        provenance_data.setdefault("source", "recon")
        provenance_data.setdefault("scan_id", asset.scan_id)
        provenance_data.setdefault("job_id", "legacy")
        provenance_data.setdefault("actor", "system")
        provenance_data.setdefault("observed_at", observed_at.isoformat())
        provenance_data.setdefault("dry_run", scan.dry_run)
        legacy_payload = {
            "tenant_id": tenant_id,
            "ip": asset.ip,
            "hostname": asset.hostname,
            "ports": sorted(set(asset.ports or [])),
            "services": sorted(set(asset.services or [])),
            "source": provenance_data["source"],
        }
        provenance_data.setdefault(
            "observation_hash",
            hashlib.sha256(
                json.dumps(legacy_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        )
        provenance = AssetProvenance.model_validate(provenance_data)
        shared_asset = SharedAsset(
            asset_id=asset.id,
            tenant_id=tenant_id,
            display_name=asset.hostname or asset.ip,
            asset_type="host",
        )
        return InventoryAsset(
            asset=shared_asset,
            asset_id=shared_asset.asset_id,
            tenant_id=shared_asset.tenant_id,
            display_name=shared_asset.display_name,
            asset_type="host",
            ip=asset.ip,
            hostname=asset.hostname,
            ports=list(asset.ports or []),
            services=list(asset.services or []),
            scan_id=asset.scan_id,
            source=provenance.source,
            discovered_at=observed_at,
            first_seen_at=asset.first_seen_at or scan.created_at,
            last_seen_at=observed_at,
            provenance=provenance,
        )

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
            duration_ms=job.duration_ms,
            recovery_count=job.recovery_count or 0,
        )

    @staticmethod
    def _duration_ms(started_at: datetime | None, completed_at: datetime | None) -> int | None:
        if started_at is None or completed_at is None:
            return None
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if completed_at.tzinfo is None:
            completed_at = completed_at.replace(tzinfo=timezone.utc)
        return max(0, int((completed_at - started_at).total_seconds() * 1000))

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)


def utcnow_iso() -> str:
    """Return an ISO timestamp for clients that need a plain string."""
    return datetime.now(timezone.utc).isoformat()
