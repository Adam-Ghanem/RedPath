import pytest
from app.core.authz import Principal, authorize_tenant, require_authenticated_analyst
from app.schemas.contracts import AttackEdge, AttackNode, AttackPathAnalysisRequest
from app.services.attack_path_risk import analyze_attack_path_risk
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
) -> AttackNode:
    return AttackNode(
        id=node_id,
        label=label,
        kind="asset" if not crown else "privilege",
        zone=zone,
        criticality=criticality,
        is_entry_point=entry,
        is_crown_jewel=crown,
    )


def edge(
    source: str,
    target: str,
    *,
    likelihood: float = 8,
    impact: float = 8,
    stealth: float = 7,
    category: str = "lateral_movement",
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


def test_attack_path_api_enforces_authentication_and_returns_analysis() -> None:
    from app.core.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    settings = Settings(
        database_url="sqlite:////tmp/redpath-attack-path-api.db",
        audit_log_path="/tmp/redpath-attack-path-api.jsonl",
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
