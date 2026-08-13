from app.core.scope import ScopePolicy, ScopeViolation
from app.schemas.contracts import AttackEdge, AttackNode, GraphRequest, WazuhAlert
from app.services.ad_detection import detect_ad_findings
from app.services.correlation import correlate_findings
from app.services.graph_engine import analyze_attack_graph
from app.services.purple import build_detection_gap_report
from app.services.recon import ReconService


def test_scope_rejects_out_of_scope_target() -> None:
    policy = ScopePolicy.from_strings(["192.168.56.0/24"])
    try:
        policy.validate_ip("8.8.8.8")
    except ScopeViolation:
        return
    raise AssertionError("out-of-scope target was accepted")


def test_recon_defaults_to_planning_only() -> None:
    service = ReconService(ScopePolicy.from_strings(["192.168.56.0/24"]))
    result = service.run(["192.168.56.10"], profile="service_inventory", dry_run=True)
    assert result.dry_run is True
    assert len(result.commands) == 1
    assert result.commands[0].tool == "nmap"
    assert "-sV" in result.commands[0].argv
    assert "enum4linux" not in result.commands[0].argv
    assert all(command.executed is False for command in result.commands)


def test_ad_detection_maps_findings_to_mitre() -> None:
    findings = detect_ad_findings(
        [
            {"asset_id": "dc01", "service_principal_name": "MSSQLSvc/db01.lab.local:1433"},
            {"asset_id": "user01", "preauth_disabled": True},
            {"asset_id": "ca01", "enrollee_supplies_subject": True, "client_auth_eku": True},
        ]
    )
    assert {finding.technique_id for finding in findings} == {"T1558.003", "T1558.004", "T1649"}


def test_graph_returns_shortest_path_and_chokepoint() -> None:
    result = analyze_attack_graph(
        GraphRequest(
            nodes=[
                AttackNode(id="foothold", label="Workstation", kind="asset"),
                AttackNode(id="svc", label="Service Account", kind="identity"),
                AttackNode(id="domain-admin", label="Domain Admin", kind="privilege"),
            ],
            edges=[
                AttackEdge(source="foothold", target="svc", technique_id="T1558.003", weight=1),
                AttackEdge(source="svc", target="domain-admin", technique_id="T1649", weight=2),
            ],
            source_node="foothold",
        )
    )
    assert result.paths[0].nodes == ["foothold", "svc", "domain-admin"]
    assert result.chokepoints[0]["node_id"] == "svc"


def test_correlation_prioritizes_path_relevant_findings() -> None:
    findings = detect_ad_findings([{"asset_id": "svc", "service_principal_name": "MSSQLSvc/db01:1433"}])
    graph_result = analyze_attack_graph(
        GraphRequest(
            nodes=[
                AttackNode(id="foothold", label="Workstation", kind="asset"),
                AttackNode(id="svc", label="svc", kind="identity"),
                AttackNode(id="domain-admin", label="Domain Admin", kind="privilege"),
            ],
            edges=[
                AttackEdge(source="foothold", target="svc", technique_id="T1558.003", weight=1),
                AttackEdge(source="svc", target="domain-admin", technique_id="T1649", weight=1),
            ],
            source_node="foothold",
        )
    )
    correlated = correlate_findings(findings, graph_result)
    assert correlated[0].technique_id == "T1558.003"
    assert "T1649" in correlated[0].related_techniques


def test_purple_report_identifies_missing_detection() -> None:
    report = build_detection_gap_report(
        ["T1558.003", "T1558.004"],
        [WazuhAlert(id="a-1", rule={"description": "T1558.003 Kerberoasting detected"})],
    )
    assert report.coverage_percent == 50.0
    assert report.gaps == ["T1558.004"]
