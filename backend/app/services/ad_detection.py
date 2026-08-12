from __future__ import annotations

from typing import Any

from app.schemas.contracts import FindingInput


def _has_any(item: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(bool(item.get(key)) for key in keys)


def detect_ad_findings(observations: list[dict[str, Any]]) -> list[FindingInput]:
    """Analyze lab-exported AD observations; this function never contacts AD."""
    findings: list[FindingInput] = []
    for item in observations:
        asset_id = str(item.get("asset_id") or item.get("hostname") or "ad-lab")
        if _has_any(item, ("service_principal_name", "spn", "kerberoastable")):
            findings.append(
                FindingInput(
                    title="Service account exposes a roastable SPN",
                    description=(
                        "The supplied lab observation indicates a service principal name "
                        "associated with an account that should be reviewed for offline ticket cracking risk."
                    ),
                    severity="high",
                    asset_id=asset_id,
                    technique_id="T1558.003",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    evidence={
                        "source": "lab_observation",
                        "keys": [
                            key for key in item if key in {"service_principal_name", "spn", "kerberoastable"}
                        ],
                    },
                )
            )
        if _has_any(item, ("preauth_disabled", "do_not_require_preauth", "asrep_roastable")):
            findings.append(
                FindingInput(
                    title="Account does not require Kerberos pre-authentication",
                    description=(
                        "The supplied lab observation indicates an account exception that can expose "
                        "an AS-REP response to offline password guessing."
                    ),
                    severity="high",
                    asset_id=asset_id,
                    technique_id="T1558.004",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    evidence={"source": "lab_observation", "preauth_disabled": True},
                )
            )
        adcs_risk_keys = ("enrollee_supplies_subject", "client_auth_eku", "broad_enrollment", "adcs_template")
        if _has_any(item, adcs_risk_keys):
            findings.append(
                FindingInput(
                    title="ADCS template requires review",
                    description=(
                        "The supplied certificate-template metadata contains an enrollment or subject-control "
                        "condition that can create an authentication-certificate abuse path."
                    ),
                    severity="critical",
                    asset_id=asset_id,
                    technique_id="T1649",
                    cvss_score=8.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
                    evidence={
                        "source": "lab_observation",
                        "matched_keys": [key for key in item if key in adcs_risk_keys],
                    },
                )
            )
    return findings
