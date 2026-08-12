from __future__ import annotations

from app.schemas.contracts import ScenarioSpec

SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        scenario_id="ad.identity-exposure-baseline",
        name="AD identity exposure baseline",
        objective="Identify identity conditions that can create credential-access paths in a synthetic AD lab.",
        tactics=["Credential Access", "Privilege Escalation"],
        technique_ids=["T1558.003", "T1558.004"],
        required_evidence=[
            "SPN-bearing service accounts",
            "Kerberos pre-authentication state",
            "Windows 4768/4769 coverage",
        ],
        safety_notes=["Use exported observations only.", "Do not request tickets, crack hashes, or modify AD objects."],
        estimated_minutes=15,
    ),
    ScenarioSpec(
        scenario_id="ad.adcs-template-review",
        name="ADCS template review",
        objective="Review certificate-template metadata for authentication-certificate abuse paths.",
        tactics=["Credential Access", "Privilege Escalation"],
        technique_ids=["T1649"],
        required_evidence=[
            "Template enrollment permissions",
            "Subject-control settings",
            "Authentication EKUs",
            "Certificate issuance alerts",
        ],
        safety_notes=["Analyze template exports; do not enroll certificates during the assessment."],
        estimated_minutes=20,
    ),
    ScenarioSpec(
        scenario_id="purple.kerberos-detection-battle",
        name="Kerberos detection battle",
        objective="Compare expected Kerberoasting and AS-REP Roasting signals against imported Wazuh evidence.",
        tactics=["Credential Access"],
        technique_ids=["T1558.003", "T1558.004"],
        required_evidence=["Synthetic Windows authentication events", "Wazuh rule IDs", "Detection timestamps"],
        safety_notes=["Use synthetic or already-exported events; do not run attack tooling."],
        estimated_minutes=25,
    ),
    ScenarioSpec(
        scenario_id="purple.path-to-domain-admin",
        name="Path to Domain Admin review",
        objective="Prioritize a modeled path using finding severity, CVSS, chokepoints, and detection gaps.",
        tactics=["Credential Access", "Privilege Escalation"],
        technique_ids=["T1558.003", "T1649"],
        required_evidence=["Attack graph", "Finding evidence", "Coverage report", "Remediation owner"],
        safety_notes=["This is an in-memory graph exercise; no privilege escalation is executed."],
        estimated_minutes=30,
    ),
)


def list_scenarios() -> list[ScenarioSpec]:
    return list(SCENARIOS)


def get_scenario(scenario_id: str) -> ScenarioSpec:
    for scenario in SCENARIOS:
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError(f"Unknown scenario: {scenario_id}")
