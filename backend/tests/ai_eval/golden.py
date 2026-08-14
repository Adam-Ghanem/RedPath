from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GoldenScenario:
    scenario_id: str
    deterministic_tier: str
    techniques: tuple[str, ...]
    evidence_terms: tuple[str, ...]
    prompt: str


_SCENARIOS = (
    (
        "kerberoast-critical",
        "critical",
        ("T1558.003",),
        ("service ticket", "tier-0"),
        "A service identity can reach a tier-0 directory asset through a recoverable service ticket.",
    ),
    (
        "asrep-high",
        "high",
        ("T1558.004",),
        ("pre-authentication", "account"),
        "An account without pre-authentication is exposed in the modeled identity path.",
    ),
    (
        "certificate-high",
        "high",
        ("T1649",),
        ("certificate template", "privilege"),
        "A certificate template relationship can enable unauthorized privileged authentication.",
    ),
    (
        "admin-share-high",
        "high",
        ("T1021.002",),
        ("admin share", "lateral"),
        "An administrative share provides a modeled lateral movement route to an application server.",
    ),
    (
        "ticket-medium",
        "medium",
        ("T1558.003",),
        ("service ticket", "workstation"),
        "A service ticket exposure reaches a non-critical workstation with limited downstream impact.",
    ),
    (
        "asrep-medium",
        "medium",
        ("T1558.004",),
        ("pre-authentication", "workstation"),
        "An account pre-authentication gap is present but the affected asset is not a crown jewel.",
    ),
    (
        "certificate-medium",
        "medium",
        ("T1649",),
        ("certificate template", "delegated"),
        "A delegated certificate template has a moderate privilege impact in the modeled graph.",
    ),
    (
        "share-medium",
        "medium",
        ("T1021.002",),
        ("admin share", "application"),
        "An administrative share reaches an application host but not a directory control asset.",
    ),
    (
        "ticket-low",
        "low",
        ("T1558.003",),
        ("service ticket", "isolated"),
        "An isolated service-ticket observation has low modeled likelihood and impact.",
    ),
    (
        "asrep-low",
        "low",
        ("T1558.004",),
        ("pre-authentication", "low-value"),
        "A pre-authentication gap is attached to a low-value isolated identity.",
    ),
    (
        "certificate-low",
        "low",
        ("T1649",),
        ("certificate template", "sandbox"),
        "A sandbox certificate template is exposed without a path to sensitive assets.",
    ),
    (
        "share-low",
        "low",
        ("T1021.002",),
        ("admin share", "isolated"),
        "An isolated admin-share relationship has low path centrality.",
    ),
    (
        "kerberoast-critical-2",
        "critical",
        ("T1558.003", "T1021.002"),
        ("service ticket", "admin share"),
        "A service ticket is followed by an admin-share route to tier-0 control.",
    ),
    (
        "certificate-critical-2",
        "critical",
        ("T1649", "T1558.004"),
        ("certificate template", "pre-authentication"),
        "A certificate template and pre-authentication chain reaches the directory crown jewel.",
    ),
    (
        "asrep-high-2",
        "high",
        ("T1558.004", "T1021.002"),
        ("pre-authentication", "lateral"),
        "A pre-authentication gap enables lateral movement to a privileged application host.",
    ),
    (
        "share-high-2",
        "high",
        ("T1021.002", "T1649"),
        ("admin share", "certificate template"),
        "An admin-share route exposes a certificate enrollment control with high impact.",
    ),
    (
        "ticket-medium-2",
        "medium",
        ("T1558.003", "T1649"),
        ("service ticket", "delegated"),
        "A service ticket reaches a delegated certificate relationship with moderate impact.",
    ),
    (
        "asrep-medium-2",
        "medium",
        ("T1558.004", "T1558.003"),
        ("pre-authentication", "service ticket"),
        "Two identity weaknesses combine but the path ends outside the critical asset zone.",
    ),
    (
        "certificate-low-2",
        "low",
        ("T1649", "T1558.004"),
        ("certificate template", "sandbox"),
        "A sandbox certificate relationship has no modeled path to sensitive assets.",
    ),
    (
        "share-low-2",
        "low",
        ("T1021.002", "T1558.003"),
        ("admin share", "isolated"),
        "An isolated share relationship has low likelihood and no evidence of privilege escalation.",
    ),
)

GOLDEN_DATASET = tuple(
    GoldenScenario(
        scenario_id=scenario_id,
        deterministic_tier=tier,
        techniques=techniques,
        evidence_terms=evidence_terms,
        prompt=prompt,
    )
    for scenario_id, tier, techniques, evidence_terms, prompt in _SCENARIOS
)
