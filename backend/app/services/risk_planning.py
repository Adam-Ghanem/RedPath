from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
from time import perf_counter
from typing import Any, Callable

from app.core.observability import MetricsRegistry
from app.db.models import AttackPathAnalysis
from app.schemas.contracts import (
    RiskBlastRadiusSummary,
    RiskCacheInvalidationEvent,
    RiskGraphSnapshot,
    RiskPolicySimulationRequest,
    RiskPolicySimulationResponse,
    RiskQueryBounds,
    RiskQueryCost,
    RiskScoreDiff,
)

SessionFactory = Callable[[], Any]
_BLOCKED_TECHNIQUE_FACTOR = 0.25


class RiskSnapshotNotFound(LookupError):
    """A server-authoritative snapshot is absent or not visible to the tenant."""


class RiskPlanningService:
    """Bounded, read-only what-if planning over persisted authorized summaries."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        metrics: MetricsRegistry,
        cache_ttl_seconds: int = 30,
        cache_max_entries: int = 256,
        max_paths: int = 500,
        max_traversal_steps: int = 100_000,
    ) -> None:
        self._session_factory = session_factory
        self._metrics = metrics
        self._cache_ttl_seconds = max(1, min(cache_ttl_seconds, 300))
        self._cache_max_entries = max(1, min(cache_max_entries, 1_000))
        self._max_paths = max(1, min(max_paths, 500))
        self._max_traversal_steps = max(1, min(max_traversal_steps, 100_000))
        self._cache: OrderedDict[str, tuple[float, RiskPolicySimulationResponse]] = OrderedDict()

    def load_snapshot(self, *, tenant_id: str, analysis_id: str) -> RiskGraphSnapshot:
        with self._session_factory() as session:
            row = (
                session.query(AttackPathAnalysis)
                .filter(AttackPathAnalysis.id == analysis_id, AttackPathAnalysis.tenant_id == tenant_id)
                .one_or_none()
            )
        if row is None:
            raise RiskSnapshotNotFound("risk analysis snapshot not found")
        summary = row.summary_json if isinstance(row.summary_json, dict) else {}
        paths = summary.get("paths", [])
        try:
            return RiskGraphSnapshot.model_validate(
                {
                    "tenant_id": row.tenant_id,
                    "analysis_id": row.id,
                    "graph_fingerprint": row.graph_fingerprint,
                    "paths": paths,
                }
            )
        except ValueError as exc:
            raise RiskSnapshotNotFound("risk analysis snapshot is unavailable") from exc

    @staticmethod
    def _scope_digest(snapshot: RiskGraphSnapshot) -> str:
        canonical = f"{snapshot.tenant_id}|{snapshot.analysis_id}|{snapshot.graph_fingerprint}"
        return sha256(canonical.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _policy_digest(request: RiskPolicySimulationRequest) -> str:
        canonical = "|".join(
            [
                request.analysis_id,
                ",".join(request.blocked_technique_ids),
                str(request.max_paths),
                str(request.max_traversal_steps),
            ]
        )
        return sha256(canonical.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def _cache_key(self, snapshot: RiskGraphSnapshot, request: RiskPolicySimulationRequest) -> str:
        return f"risk-sim:{self._scope_digest(snapshot)}:{self._policy_digest(request)}"

    def _cache_get(self, key: str) -> RiskPolicySimulationResponse | None:
        now = perf_counter()
        cached = self._cache.get(key)
        if cached is None:
            return None
        expires_at, response = cached
        if expires_at <= now:
            self._cache.pop(key, None)
            return None
        self._cache.move_to_end(key)
        return response.model_copy(deep=True)

    def _cache_put(self, key: str, response: RiskPolicySimulationResponse) -> None:
        self._cache[key] = (perf_counter() + self._cache_ttl_seconds, response.model_copy(deep=True))
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_max_entries:
            self._cache.popitem(last=False)

    def invalidate(
        self,
        *,
        tenant_id: str,
        analysis_id: str,
        graph_fingerprint: str,
        reason: str,
    ) -> RiskCacheInvalidationEvent:
        snapshot = RiskGraphSnapshot(
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            graph_fingerprint=graph_fingerprint,
            paths=[],
        )
        scope_digest = self._scope_digest(snapshot)
        prefix = f"risk-sim:{scope_digest}:"
        for key in list(self._cache):
            if key.startswith(prefix):
                self._cache.pop(key, None)
        return RiskCacheInvalidationEvent(
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            graph_fingerprint=graph_fingerprint,
            reason=reason,
            invalidation_key=f"risk-cache:{scope_digest}",
        )

    def simulate(
        self,
        request: RiskPolicySimulationRequest,
        *,
        authorized_tenant_id: str,
    ) -> RiskPolicySimulationResponse:
        if not authorized_tenant_id:
            raise PermissionError("authenticated tenant is required")
        started = perf_counter()
        self._metrics.increment_telemetry("risk_query_requests_total")
        snapshot = self.load_snapshot(tenant_id=authorized_tenant_id, analysis_id=request.analysis_id)
        bounds = RiskQueryBounds(
            max_paths=min(request.max_paths, self._max_paths),
            max_traversal_steps=min(request.max_traversal_steps, self._max_traversal_steps),
        )
        cache_key = self._cache_key(snapshot, request)
        cached = self._cache_get(cache_key)
        if cached is not None:
            self._metrics.increment_telemetry("risk_query_cache_hits_total")
            elapsed_ms = int((perf_counter() - started) * 1000)
            cached.cache_hit = True
            cached.query_cost.duration_ms = elapsed_ms
            return cached

        blocked = set(request.blocked_technique_ids)
        score_diffs: list[RiskScoreDiff] = []
        affected_asset_ids: list[str] = []
        affected_evidence_ids: list[str] = []
        seen_assets: set[str] = set()
        seen_evidence: set[str] = set()
        traversal_steps = 0
        truncated = False
        paths_considered = 0
        for path in snapshot.paths:
            if paths_considered >= bounds.max_paths:
                truncated = True
                break
            path_cost = 1 + path.hop_count + len(path.technique_ids)
            if traversal_steps + path_cost > bounds.max_traversal_steps:
                truncated = True
                break
            traversal_steps += path_cost
            paths_considered += 1
            blocked_for_path = sorted(blocked.intersection(path.technique_ids))
            simulated_score = path.risk_score * (_BLOCKED_TECHNIQUE_FACTOR if blocked_for_path else 1.0)
            delta = round(simulated_score - path.risk_score, 4)
            score_diffs.append(
                RiskScoreDiff(
                    path_id=path.path_id,
                    baseline_score=path.risk_score,
                    simulated_score=round(simulated_score, 4),
                    delta=delta,
                    baseline_level=path.risk_level,
                    simulated_level=self._risk_level(simulated_score),
                    blocked_by_technique_ids=blocked_for_path,
                )
            )
            if blocked_for_path:
                for value in path.asset_ids:
                    if value not in seen_assets and len(affected_asset_ids) < bounds.max_asset_ids:
                        seen_assets.add(value)
                        affected_asset_ids.append(value)
                for value in path.evidence_ids:
                    if value not in seen_evidence and len(affected_evidence_ids) < bounds.max_evidence_ids:
                        seen_evidence.add(value)
                        affected_evidence_ids.append(value)

        if truncated:
            self._metrics.increment_telemetry("risk_query_truncated_total")
        baseline_score = max((item.baseline_score for item in score_diffs), default=0.0)
        simulated_score = max((item.simulated_score for item in score_diffs), default=0.0)
        elapsed_ms = int((perf_counter() - started) * 1000)
        self._metrics.set_telemetry_gauge("risk_query_last_duration_ms", elapsed_ms)
        response = RiskPolicySimulationResponse(
            tenant_id=snapshot.tenant_id,
            analysis_id=snapshot.analysis_id,
            graph_fingerprint=snapshot.graph_fingerprint,
            blocked_technique_ids=sorted(blocked),
            score_diffs=score_diffs,
            blast_radius=RiskBlastRadiusSummary(
                affected_path_count=sum(1 for item in score_diffs if item.blocked_by_technique_ids),
                affected_asset_ids=affected_asset_ids,
                affected_evidence_ids=affected_evidence_ids,
                baseline_score=baseline_score,
                simulated_score=simulated_score,
                score_delta=round(simulated_score - baseline_score, 4),
            ),
            query_cost=RiskQueryCost(
                paths_considered=paths_considered,
                traversal_steps=traversal_steps,
                truncated=truncated,
                duration_ms=elapsed_ms,
                bounds=bounds,
            ),
            cache_key=cache_key,
            cache_hit=False,
        )
        self._cache_put(cache_key, response)
        return response
