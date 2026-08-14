import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from app.core.authz import Principal, authorize_tenant, require_authenticated_analyst
from app.core.observability import MetricsRegistry
from app.db.models import Asset, AttackPathAnalysis, EvidenceItem, ScanRun, create_session_factory
from app.schemas.contracts import (
    AttackEdge,
    AttackNode,
    AttackPathAnalysisRequest,
    RiskGraphSnapshot,
    RiskPolicySimulationRequest,
)
from app.services.attack_path_risk import analyze_attack_path_risk, to_persistence_record
from app.services.risk_planning import RiskPlanningService, RiskSnapshotNotFound
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request


def node(
    node_id: str,
    label: str,
    *,
    zone: str = "on_prem",
    criticality: float = 0.0,
    entry: bool = False,
    crown: bool = False,
    asset_id: str | None = None,
) -> AttackNode:
    return AttackNode(
        id=node_id,
        label=label,
        kind="asset" if not crown else "privilege",
        zone=zone,
        criticality=criticality,
        is_entry_point=entry,
        is_crown_jewel=crown,
        asset_id=asset_id,
    )


def edge(
    source: str,
    target: str,
    *,
    likelihood: float = 8,
    impact: float = 8,
    stealth: float = 7,
    category: str = "lateral_movement",
    evidence_ids: list[str] | None = None,
    **kwargs: object,
) -> AttackEdge:
    return AttackEdge(
        source=source,
        target=target,
        technique_id="T1021.001",
        category=category,
        likelihood=likelihood,
        impact=impact,
        stealth=stealth,
        rationale="Recorded authorized relationship",
        prerequisites=["documented access"],
        mitre_techniques=["T1021.001"],
        hardening_action="Restrict and monitor the relationship.",
        evidence_ids=evidence_ids or [],
        **kwargs,
    )


def test_ranks_paths_and_explains_weighted_score() -> None:
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[
            node("entry", "Authorized foothold", entry=True),
            node("choke", "Privileged service", criticality=0.5),
            node("crown", "Production identity", criticality=1.0, crown=True),
            node("alternate", "Alternate identity"),
        ],
        edges=[
            edge("entry", "choke", likelihood=9, impact=7, stealth=8),
            edge("choke", "crown", likelihood=8, impact=9, stealth=6),
            edge("entry", "alternate", likelihood=4, impact=5, stealth=4),
            edge("alternate", "crown", likelihood=4, impact=5, stealth=4),
        ],
    )

    result = analyze_attack_path_risk(request)

    assert result.graph_summary.viable_path_count == 2
    assert result.ranked_paths[0].hops == ["entry", "choke", "crown"]
    assert result.ranked_paths[0].composite_score == 8.4
    assert result.ranked_paths[0].risk_score == 84.0
    assert result.ranked_paths[0].risk_level == "critical"
    assert result.ranked_paths[0].explanation.factors[0].dimension == "likelihood"
    assert "T1021.001" in result.ranked_paths[0].mitre_techniques


def test_phase2_links_assets_evidence_and_remediation_priority_deterministically() -> None:
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[
            node("entry", "Authorized foothold", entry=True, asset_id="asset-entry"),
            node("choke", "Privileged service", criticality=0.5, asset_id="asset-choke"),
            node("crown", "Production identity", criticality=1.0, crown=True, asset_id="asset-crown"),
        ],
        edges=[
            edge("entry", "choke", evidence_ids=["evidence-entry-choke"]),
            edge("choke", "crown", evidence_ids=["evidence-choke-crown"]),
        ],
    )
    authorized_assets = {"asset-entry", "asset-choke", "asset-crown"}

    first = analyze_attack_path_risk(request, authorized_asset_ids=authorized_assets)
    second = analyze_attack_path_risk(request, authorized_asset_ids=authorized_assets)
    path = first.ranked_paths[0]
    record = to_persistence_record(first, actor_id="user-1")

    assert first.analysis_id == second.analysis_id
    assert first.graph_fingerprint == second.graph_fingerprint
    assert path.asset_ids == ["asset-entry", "asset-choke", "asset-crown"]
    assert path.evidence_ids == ["evidence-entry-choke", "evidence-choke-crown"]
    assert path.remediation_priority == "critical"
    assert path.remediation_ids == [first.remediation_links[0].remediation_link_id]
    assert first.remediation_links[0].priority == "critical"
    assert first.remediation_links[0].rationale == path.explanation.remediation_rationale
    assert record.actor_id == "user-1"
    assert record.tenant_id == "tenant-a"


def test_phase2_rejects_asset_references_outside_tenant_inventory() -> None:
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[
            node("entry", "Entry", entry=True, asset_id="asset-not-authorized"),
            node("crown", "Crown", crown=True),
        ],
        edges=[edge("entry", "crown")],
    )

    with pytest.raises(PermissionError, match="outside the authenticated tenant inventory"):
        analyze_attack_path_risk(request, authorized_asset_ids={"asset-other"})


def test_phase2_rejects_evidence_references_outside_tenant_inventory() -> None:
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[node("entry", "Entry", entry=True), node("crown", "Crown", crown=True)],
        edges=[edge("entry", "crown", evidence_ids=["evidence-not-authorized"])],
    )

    with pytest.raises(PermissionError, match="outside the authenticated tenant evidence inventory"):
        analyze_attack_path_risk(request, authorized_evidence_ids={"evidence-other"})


def test_phase2_reports_bounded_path_enumeration() -> None:
    branch_nodes = [node(f"branch-{index}", f"Branch {index}") for index in range(6)]
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[node("entry", "Entry", entry=True), *branch_nodes, node("crown", "Crown", crown=True)],
        edges=[
            *[edge("entry", branch.id) for branch in branch_nodes],
            *[edge(branch.id, "crown") for branch in branch_nodes],
        ],
        max_paths=2,
    )

    result = analyze_attack_path_risk(request)

    assert len(result.ranked_paths) == 2
    assert result.graph_summary.truncated is True
    assert any("max_paths=2" in warning for warning in result.warnings)


def test_hybrid_path_is_explicitly_labeled_and_returned_as_cloud_path() -> None:
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[
            node("vpn", "VPN entry", zone="on_prem", entry=True),
            node("role", "Cloud role", zone="cloud"),
            node("vault", "Cloud secrets vault", zone="cloud", criticality=1.0, crown=True),
        ],
        edges=[
            edge("vpn", "role", category="cloud_privilege_abuse", hybrid=True),
            edge("role", "vault", category="cloud_privilege_abuse"),
        ],
    )

    result = analyze_attack_path_risk(request)

    assert len(result.cloud_paths) == 1
    assert result.ranked_paths[0].is_hybrid is True
    assert result.ranked_paths[0].path_id == result.cloud_paths[0]
    assert "on-premises/cloud boundary" in " ".join(result.ranked_paths[0].explanation.assumptions)


def test_chokepoint_priority_and_unreachable_crown_jewel_are_reported() -> None:
    request = AttackPathAnalysisRequest(
        tenant_id="tenant-a",
        nodes=[
            node("entry", "Entry", entry=True),
            node("choke", "Shared control"),
            node("reachable", "Reachable crown", crown=True),
            node("unreachable", "Unreachable crown", crown=True),
        ],
        edges=[edge("entry", "choke"), edge("choke", "reachable")],
    )

    result = analyze_attack_path_risk(request)

    assert result.unreachable_crown_jewels == ["unreachable"]
    assert result.choke_points[0].node_id == "choke"
    assert result.choke_points[0].paths_blocked == 1
    assert result.choke_points[0].priority_class == "P2"
    assert any("no viable path" in warning for warning in result.warnings)


def test_graph_rejects_unknown_edge_endpoints_and_missing_scope_anchors() -> None:
    with pytest.raises(ValueError, match="unknown node"):
        analyze_attack_path_risk(
            AttackPathAnalysisRequest(
                tenant_id="tenant-a",
                nodes=[node("entry", "Entry", entry=True), node("crown", "Crown", crown=True)],
                edges=[edge("entry", "missing")],
            )
        )

    with pytest.raises(ValueError, match="entry point"):
        analyze_attack_path_risk(
            AttackPathAnalysisRequest(
                tenant_id="tenant-a",
                nodes=[node("entry", "Entry"), node("crown", "Crown", crown=True)],
                edges=[],
            )
        )


def test_contract_rejects_unbounded_analysis_parameters() -> None:
    with pytest.raises(ValidationError):
        AttackPathAnalysisRequest(
            tenant_id="tenant-a",
            nodes=[node("entry", "Entry", entry=True), node("crown", "Crown", crown=True)],
            max_hops=13,
        )


def request_with_principal(principal: dict[str, object] | None) -> Request:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/attack-paths/analyze",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("testclient", 1234),
            "scheme": "http",
        }
    )
    if principal is not None:
        request.state.principal = principal
    return request


def test_attack_path_authorization_requires_analyst_role_and_tenant_access() -> None:
    principal = Principal(subject="analyst-1", roles=frozenset({"analyst"}), tenant_ids=frozenset({"tenant-a"}))
    assert require_authenticated_analyst(
        request_with_principal({"subject": "analyst-1", "roles": ["analyst"], "tenant_ids": ["tenant-a"]})
    ) == principal
    authorize_tenant(principal, "tenant-a")
    with pytest.raises(HTTPException) as denied:
        authorize_tenant(principal, "tenant-b")
    assert denied.value.status_code == 403


def test_attack_path_authorization_rejects_missing_or_wrong_role() -> None:
    with pytest.raises(HTTPException) as missing:
        require_authenticated_analyst(request_with_principal(None))
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as wrong_role:
        require_authenticated_analyst(
            request_with_principal({"subject": "viewer-1", "roles": ["viewer"], "tenant_ids": ["tenant-a"]})
        )
    assert wrong_role.value.status_code == 403


def test_attack_path_api_links_tenant_inventory_and_evidence() -> None:
    from app.core.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    settings = Settings(
        database_url=f"sqlite:////tmp/redpath-attack-path-linkage-{uuid4().hex}.db",
        audit_log_path=f"/tmp/redpath-attack-path-linkage-{uuid4().hex}.jsonl",
        auth_bootstrap_token="attack-path-linkage-bootstrap-token",
    )
    client = TestClient(create_app(settings))
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "attack-path-linkage",
            "tenant_name": "Attack Path Linkage Test Tenant",
            "username": "attack-path-linkage-admin",
            "password": "attack-path-linkage-admin-password",
        },
    )
    assert bootstrap.status_code == 201
    headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
    tenant_id = client.get("/api/v1/auth/me", headers=headers).json()["tenant_id"]
    session_factory = create_session_factory(settings.database_url)
    created_at = datetime.now(timezone.utc)
    with session_factory() as session:
        session.add(
            ScanRun(
                id="scan-linkage",
                tenant_id=tenant_id,
                mode="recon",
                dry_run=True,
                targets=["192.0.2.10"],
                warnings=[],
                created_at=created_at,
            )
        )
        session.add(
            Asset(
                id="asset-linkage",
                tenant_id=tenant_id,
                scan_id="scan-linkage",
                ip="192.0.2.10",
                hostname="fixture-host",
                ports=[],
                services=[],
                metadata_json={},
            )
        )
        session.add(
            EvidenceItem(
                id="evidence-linkage",
                tenant_id=tenant_id,
                evidence_type="fixture",
                source="authorized-fixture",
                title="Fixture evidence",
                sha256="0" * 64,
                technique_id="T1021.001",
                review_status="accepted",
                notes="Synthetic evidence metadata only",
                created_at=created_at,
            )
        )
        session.commit()

    payload = AttackPathAnalysisRequest(
        tenant_id=tenant_id,
        nodes=[
            node("entry", "Fixture entry", entry=True, asset_id="asset-linkage"),
            node("crown", "Fixture crown", criticality=1.0, crown=True),
        ],
        edges=[edge("entry", "crown", evidence_ids=["evidence-linkage"])],
    ).model_dump()
    response = client.post("/api/v1/attack-paths/analyze", json=payload, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["asset_ids"] == ["asset-linkage"]
    assert body["evidence_ids"] == ["evidence-linkage"]
    assert body["remediation_links"][0]["priority"] == "critical"
    assert body["remediation_links"][0]["tenant_id"] == tenant_id


def test_attack_path_api_enforces_authentication_and_returns_analysis() -> None:
    from app.core.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    settings = Settings(
        database_url=f"sqlite:////tmp/redpath-attack-path-api-{uuid4().hex}.db",
        audit_log_path=f"/tmp/redpath-attack-path-api-{uuid4().hex}.jsonl",
        auth_bootstrap_token="attack-path-test-bootstrap-token",
    )
    client = TestClient(create_app(settings))
    unauthenticated_payload = AttackPathAnalysisRequest(
        tenant_id="unauthenticated-tenant",
        nodes=[node("entry", "Entry", entry=True), node("crown", "Crown", criticality=1.0, crown=True)],
        edges=[edge("entry", "crown")],
    ).model_dump()
    unauthenticated = client.post("/api/v1/attack-paths/analyze", json=unauthenticated_payload)
    assert unauthenticated.status_code == 401

    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "attack-path",
            "tenant_name": "Attack Path Test Tenant",
            "username": "attack-path-admin",
            "password": "attack-path-admin-password",
        },
    )
    assert bootstrap.status_code == 201
    headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
    me = client.get("/api/v1/auth/me", headers=headers)
    payload = AttackPathAnalysisRequest(
        tenant_id=me.json()["tenant_id"],
        nodes=[node("entry", "Entry", entry=True), node("crown", "Crown", criticality=1.0, crown=True)],
        edges=[edge("entry", "crown")],
    ).model_dump()
    authorized = client.post("/api/v1/attack-paths/analyze", json=payload, headers=headers)

    assert authorized.status_code == 200
    assert authorized.json()["ranked_paths"][0]["risk_level"] == "critical"
    assert authorized.json()["tenant_id"] == me.json()["tenant_id"]


RISK_PHASE4_FIXTURE = Path(__file__).parent / "fixtures" / "risk_policy_phase4.json"


def _seed_phase4_snapshot(tmp_path: Path, tenant_id: str = "tenant-a") -> tuple[RiskPlanningService, MetricsRegistry]:
    fixture = json.loads(RISK_PHASE4_FIXTURE.read_text(encoding="utf-8"))
    fixture["tenant_id"] = tenant_id
    fixture["analysis_id"] = f"analysis-{tenant_id.split('-')[-1]}"
    snapshot = RiskGraphSnapshot.model_validate(fixture)
    database_url = f"sqlite:///{tmp_path / f'{tenant_id}.db'}"
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        session.add(
            AttackPathAnalysis(
                id=snapshot.analysis_id,
                tenant_id=tenant_id,
                actor_id="server-actor",
                graph_fingerprint=snapshot.graph_fingerprint,
                summary_json={"paths": [path.model_dump(mode="json") for path in snapshot.paths]},
            )
        )
        session.commit()
    metrics = MetricsRegistry()
    return RiskPlanningService(session_factory, metrics=metrics, cache_ttl_seconds=30), metrics


def test_policy_simulation_is_deterministic_sensitive_and_cached(tmp_path: Path) -> None:
    service, metrics = _seed_phase4_snapshot(tmp_path)
    request = RiskPolicySimulationRequest(analysis_id="analysis-a", blocked_technique_ids=["T1021"])

    first = service.simulate(request, authorized_tenant_id="tenant-a")
    second = service.simulate(request, authorized_tenant_id="tenant-a")

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert first.cache_key == second.cache_key
    assert [item.simulated_score for item in first.score_diffs] == [21.0, 13.75]
    assert first.blast_radius.affected_path_count == 2
    assert first.blast_radius.affected_asset_ids == [
        "asset-workstation-a",
        "asset-domain-a",
        "asset-server-a",
    ]
    assert first.query_cost.truncated is False
    assert metrics.snapshot()["telemetry_counters"]["risk_query_requests_total"] == 2
    assert metrics.snapshot()["telemetry_counters"]["risk_query_cache_hits_total"] == 1
    prometheus = metrics.prometheus()
    assert "tenant-a" not in prometheus
    assert "analysis-a" not in prometheus


def test_policy_simulation_is_tenant_safe_and_client_cannot_supply_snapshot(tmp_path: Path) -> None:
    service, _metrics = _seed_phase4_snapshot(tmp_path)
    with pytest.raises(RiskSnapshotNotFound):
        service.simulate(
            RiskPolicySimulationRequest(analysis_id="analysis-a", blocked_technique_ids=["T1021"]),
            authorized_tenant_id="tenant-b",
        )
    with pytest.raises(ValidationError):
        RiskPolicySimulationRequest.model_validate(
            {
                "analysis_id": "analysis-a",
                "blocked_technique_ids": ["T1021"],
                "snapshot": {"tenant_id": "tenant-b"},
            }
        )


def test_policy_simulation_honors_path_and_traversal_bounds_and_invalidates_cache(tmp_path: Path) -> None:
    service, metrics = _seed_phase4_snapshot(tmp_path)
    bounded = service.simulate(
        RiskPolicySimulationRequest(
            analysis_id="analysis-a",
            blocked_technique_ids=["T1021"],
            max_paths=1,
            max_traversal_steps=100,
        ),
        authorized_tenant_id="tenant-a",
    )
    assert bounded.query_cost.paths_considered == 1
    assert bounded.query_cost.truncated is True
    assert metrics.snapshot()["telemetry_counters"]["risk_query_truncated_total"] == 1

    invalidation = service.invalidate(
        tenant_id="tenant-a",
        analysis_id="analysis-a",
        graph_fingerprint="a" * 64,
        reason="snapshot_changed",
    )
    assert invalidation.tenant_id == "tenant-a"
    refreshed = service.simulate(
        RiskPolicySimulationRequest(
            analysis_id="analysis-a",
            blocked_technique_ids=["T1021"],
            max_paths=1,
            max_traversal_steps=100,
        ),
        authorized_tenant_id="tenant-a",
    )
    assert refreshed.cache_hit is False


def test_risk_simulation_api_uses_registered_tenant_snapshot() -> None:
    from app.core.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    settings = Settings(
        database_url=f"sqlite:////tmp/redpath-risk-simulation-{uuid4().hex}.db",
        audit_log_path=f"/tmp/redpath-risk-simulation-{uuid4().hex}.jsonl",
        auth_bootstrap_token="risk-simulation-bootstrap-token",
    )
    client = TestClient(create_app(settings))
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "risk-simulation",
            "tenant_name": "Risk Simulation Test Tenant",
            "username": "risk-simulation-admin",
            "password": "risk-simulation-admin-password",
        },
    )
    assert bootstrap.status_code == 201
    headers = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
    tenant_id = client.get("/api/v1/auth/me", headers=headers).json()["tenant_id"]
    analysis = client.post(
        "/api/v1/attack-paths/analyze",
        json=AttackPathAnalysisRequest(
            tenant_id=tenant_id,
            nodes=[node("entry", "Entry", entry=True), node("crown", "Crown", criticality=1.0, crown=True)],
            edges=[edge("entry", "crown")],
        ).model_dump(),
        headers=headers,
    )
    assert analysis.status_code == 200

    simulation = client.post(
        "/api/v1/risk/simulate",
        json={"analysis_id": analysis.json()["analysis_id"], "blocked_technique_ids": ["T1021.001"]},
        headers=headers,
    )
    assert simulation.status_code == 200, simulation.text
    assert simulation.json()["tenant_id"] == tenant_id
    assert simulation.json()["blast_radius"]["affected_path_count"] == 1
    score_diff = simulation.json()["score_diffs"][0]
    assert score_diff["simulated_score"] < score_diff["baseline_score"]

    missing = client.post(
        "/api/v1/risk/simulate",
        json={"analysis_id": "analysis-from-another-tenant"},
        headers=headers,
    )
    assert missing.status_code == 404
