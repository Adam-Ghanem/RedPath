from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    description: str
    evidence_hints: tuple[str, ...]
    remediation: tuple[str, ...]


TECHNIQUES: dict[str, Technique] = {
    "T1558.003": Technique(
        technique_id="T1558.003",
        name="Kerberoasting",
        tactic="Credential Access",
        description="Abuse of service principal names to request service tickets that may be cracked offline.",
        evidence_hints=("service_principal_name", "rc4_tgs", "event_4769"),
        remediation=(
            "Prefer group managed service accounts where possible.",
            "Use long, unique service-account secrets and rotate them.",
            "Monitor unusual TGS requests and RC4 usage.",
        ),
    ),
    "T1558.004": Technique(
        technique_id="T1558.004",
        name="AS-REP Roasting",
        tactic="Credential Access",
        description="Request AS-REP responses for accounts that do not require Kerberos pre-authentication.",
        evidence_hints=("preauth_disabled", "event_4768", "preauth_type_0", "rc4_asrep"),
        remediation=(
            "Require Kerberos pre-authentication for normal user accounts.",
            "Use strong, unique passwords for accounts that must retain exceptions.",
            "Alert on Event ID 4768 with pre-authentication type 0 and unusual enumeration.",
        ),
    ),
    "T1649": Technique(
        technique_id="T1649",
        name="Steal or Forge Authentication Certificates",
        tactic="Credential Access",
        description="Abuse or theft of authentication certificates to impersonate users or access services.",
        evidence_hints=("certificate_template", "enrollee_supplies_subject", "client_auth_eku", "adcs_template"),
        remediation=(
            "Review certificate-template enrollment permissions and remove broad enrollment rights.",
            "Require manager or CA approval for privileged certificate templates.",
            "Monitor certificate issuance and authentication events for anomalous subjects.",
        ),
    ),
}


def get_technique(technique_id: str) -> Technique:
    try:
        return TECHNIQUES[technique_id]
    except KeyError as exc:
        raise KeyError(f"Unsupported MITRE technique: {technique_id}") from exc


def technique_to_dict(technique: Technique) -> dict[str, Any]:
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "tactic": technique.tactic,
        "description": technique.description,
        "detection_guidance": list(technique.evidence_hints),
        "remediation": list(technique.remediation),
    }


def all_techniques() -> list[dict[str, Any]]:
    return [technique_to_dict(item) for item in TECHNIQUES.values()]
