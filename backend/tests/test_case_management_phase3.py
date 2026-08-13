from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.db.models import RiskAcceptance, create_session_factory
from app.main import create_app
from fastapi.testclient import TestClient

DB_PATH = Path("/tmp") / f"redpath-phase3-cases-{uuid4().hex}.db"
settings = Settings(
    database_url=f"sqlite:///{DB_PATH}",
    audit_log_path=f"/tmp/redpath-phase3-cases-{uuid4().hex}.jsonl",
    auth_bootstrap_token="phase3-cases-bootstrap-token",
    rate_limit_requests_per_minute=300,
)
raw_client = TestClient(create_app(settings))
bootstrap = raw_client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "cases-alpha",
        "tenant_name": "Cases Alpha",
        "username": "phase3-admin",
        "password": "phase3-admin-password",
    },
)
assert bootstrap.status_code == 201
ADMIN_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def login(tenant_slug: str, username: str, password: str) -> dict[str, str]:
    response = raw_client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": tenant_slug, "username": username, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_case() -> dict:
    response = raw_client.post(
        "/api/v1/cases",
        headers=ADMIN_HEADERS,
        json={
            "name": f"Case management {uuid4().hex[:8]}",
            "objective": "Validate mature authorized case-management controls in a defensive lab.",
            "scope_snapshot": ["192.168.56.0/24"],
        },
    )
    assert response.status_code == 201
    return response.json()


def create_evidence(case_id: str) -> dict:
    response = raw_client.post(
        "/api/v1/evidence",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case_id,
            "evidence_type": "defensive_fixture",
            "source": "lab/fixtures/case-management.json",
            "title": "Case management evidence",
            "sha256": "b" * 64,
            "technique_id": "T1558.003",
            "notes": "metadata only; password=must-not-leak",
        },
    )
    assert response.status_code == 201
    return response.json()


def accept_and_verify_evidence(evidence: dict) -> None:
    reviewed = raw_client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        headers=ADMIN_HEADERS,
        json={"review_status": "accepted", "notes": "Evidence review complete."},
    )
    assert reviewed.status_code == 200
    custody = raw_client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/custody",
        headers=ADMIN_HEADERS,
        json={"decision": "verified", "manifest_sha256": evidence["manifest_sha256"]},
    )
    assert custody.status_code == 201
    assert custody.json()["actor"] == "phase3-admin"


def create_remediation(case_id: str, **overrides: object) -> dict:
    payload = {
        "campaign_id": case_id,
        "finding_title": "Case management remediation",
        "technique_id": "T1558.003",
        "recommendation": "Apply a documented defensive control and validate the result safely.",
        "owner": "case-team",
        "priority": "high",
    }
    payload.update(overrides)
    response = raw_client.post("/api/v1/remediations", headers=ADMIN_HEADERS, json=payload)
    assert response.status_code == 201
    return response.json()


def test_assignment_is_tenant_validated_and_rbac_protected() -> None:
    user = raw_client.post(
        "/api/v1/auth/users",
        headers=ADMIN_HEADERS,
        json={"username": "case-analyst", "password": "case-analyst-password", "roles": ["analyst"]},
    )
    assert user.status_code == 201
    viewer = raw_client.post(
        "/api/v1/auth/users",
        headers=ADMIN_HEADERS,
        json={"username": "case-viewer", "password": "case-viewer-password", "roles": ["viewer"]},
    )
    assert viewer.status_code == 201

    case = create_case()
    remediation = create_remediation(case["campaign_id"], assigned_to="case-analyst")
    assert remediation["assigned_to"] == "case-analyst"

    reassigned = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/assignment",
        headers=ADMIN_HEADERS,
        json={"assigned_to": "phase3-admin"},
    )
    assert reassigned.status_code == 200
    assert reassigned.json()["assigned_to"] == "phase3-admin"

    unknown_assignee = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/assignment",
        headers=ADMIN_HEADERS,
        json={"assigned_to": "not-a-tenant-user"},
    )
    assert unknown_assignee.status_code == 404

    viewer_headers = login("cases-alpha", "case-viewer", "case-viewer-password")
    denied = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/assignment",
        headers=viewer_headers,
        json={"assigned_to": "case-analyst"},
    )
    assert denied.status_code == 403

    history = raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/governance-history",
        headers=ADMIN_HEADERS,
    )
    assert history.status_code == 200
    assert any(
        event["event_type"] == "remediation.assigned" and event["actor"] == "phase3-admin"
        for event in history.json()
    )


def test_custody_requires_matching_manifest_and_is_tenant_safe() -> None:
    case = create_case()
    evidence = create_evidence(case["campaign_id"])
    bad_manifest = raw_client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/custody",
        headers=ADMIN_HEADERS,
        json={"decision": "verified", "manifest_sha256": "a" * 64},
    )
    assert bad_manifest.status_code == 409

    accept_and_verify_evidence(evidence)
    custody = raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/custody-history",
        headers=ADMIN_HEADERS,
    )
    assert custody.status_code == 200
    assert len(custody.json()) == 1
    assert custody.json()[0]["manifest_sha256"] == evidence["manifest_sha256"]

    tenant = raw_client.post(
        "/api/v1/auth/tenants",
        headers=ADMIN_HEADERS,
        json={
            "slug": "cases-bravo",
            "name": "Cases Bravo",
            "admin_username": "cases-bravo-admin",
            "admin_password": "cases-bravo-password",
        },
    )
    assert tenant.status_code == 201
    bravo_headers = login("cases-bravo", "cases-bravo-admin", "cases-bravo-password")
    assert raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/custody-history", headers=bravo_headers
    ).status_code == 404
    assert raw_client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/custody",
        headers=bravo_headers,
        json={"decision": "verified", "manifest_sha256": evidence["manifest_sha256"]},
    ).status_code == 404


def test_remediation_verification_is_required_for_case_close() -> None:
    case = create_case()
    evidence = create_evidence(case["campaign_id"])
    accept_and_verify_evidence(evidence)
    remediation = create_remediation(case["campaign_id"])

    started = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        headers=ADMIN_HEADERS,
        json={"status": "in_progress"},
    )
    assert started.status_code == 200
    resolved = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        headers=ADMIN_HEADERS,
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["verification_status"] == "pending"

    before_verification = raw_client.patch(
        f"/api/v1/cases/{case['campaign_id']}/status",
        headers=ADMIN_HEADERS,
        json={"status": "closed"},
    )
    assert before_verification.status_code == 409

    verified = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/verification",
        headers=ADMIN_HEADERS,
        json={"decision": "verified", "note": "Independent defensive validation complete."},
    )
    assert verified.status_code == 200
    assert verified.json()["verification_status"] == "verified"

    closed = raw_client.patch(
        f"/api/v1/cases/{case['campaign_id']}/status",
        headers=ADMIN_HEADERS,
        json={"status": "closed"},
    )
    assert closed.status_code == 200

    reject_closed = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/verification",
        headers=ADMIN_HEADERS,
        json={"decision": "rejected"},
    )
    assert reject_closed.status_code == 409


def test_risk_acceptance_approval_expiry_sla_escalation_and_export() -> None:
    case = create_case()
    evidence = create_evidence(case["campaign_id"])
    accept_and_verify_evidence(evidence)
    remediation = create_remediation(
        case["campaign_id"],
        due_date=(date.today() - timedelta(days=1)).isoformat(),
    )

    acceptance = raw_client.post(
        "/api/v1/risk-acceptances",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "remediation_id": remediation["remediation_id"],
            "finding_title": "Temporary risk acceptance",
            "rationale": "Temporary acceptance while a safe defensive fix is validated.",
            "expires_on": (date.today() + timedelta(days=30)).isoformat(),
        },
    )
    assert acceptance.status_code == 201
    acceptance_id = acceptance.json()["acceptance_id"]
    assert acceptance.json()["approval_status"] == "approved"
    assert acceptance.json()["approved_by"] == "phase3-admin"

    revoked = raw_client.patch(
        f"/api/v1/risk-acceptances/{acceptance_id}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "revoke", "note": "Review requires a fresh bounded approval."},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    reapproved = raw_client.patch(
        f"/api/v1/risk-acceptances/{acceptance_id}/decision",
        headers=ADMIN_HEADERS,
        json={
            "decision": "approve",
            "expires_on": (date.today() + timedelta(days=45)).isoformat(),
            "note": "Fresh bounded approval recorded.",
        },
    )
    assert reapproved.status_code == 200
    assert reapproved.json()["approval_status"] == "approved"

    expiring = raw_client.post(
        "/api/v1/risk-acceptances",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "remediation_id": remediation["remediation_id"],
            "finding_title": "Expired acceptance fixture",
            "rationale": "Fixture for the explicit expiry workflow and safe failure behavior.",
            "expires_on": (date.today() + timedelta(days=2)).isoformat(),
        },
    )
    assert expiring.status_code == 201
    expiring_id = expiring.json()["acceptance_id"]
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        row = session.get(RiskAcceptance, expiring_id)
        assert row is not None
        row.expires_on = (date.today() - timedelta(days=1)).isoformat()
        session.commit()

    expired = raw_client.post(
        f"/api/v1/risk-acceptances/{expiring_id}/expire",
        headers=ADMIN_HEADERS,
    )
    assert expired.status_code == 200
    assert expired.json()["status"] == "expired"
    assert expired.json()["approval_status"] == "expired"

    sla = raw_client.get("/api/v1/remediations/sla", headers=ADMIN_HEADERS)
    assert sla.status_code == 200
    assert any(
        item["remediation_id"] == remediation["remediation_id"] and item["state"] == "overdue"
        for item in sla.json()
    )
    escalations = raw_client.get("/api/v1/remediations/escalations", headers=ADMIN_HEADERS)
    assert escalations.status_code == 200
    assert any(item["remediation_id"] == remediation["remediation_id"] for item in escalations.json())

    export = raw_client.get(f"/api/v1/cases/{case['campaign_id']}/export", headers=ADMIN_HEADERS)
    assert export.status_code == 200
    payload = export.json()
    assert payload["schema_version"] == "case-export.v3"
    assert payload["actor"] == "phase3-admin"
    assert payload["custody_history"]
    assert payload["risk_acceptances"]
    assert payload["sla_escalations"]
    assert payload["manifest_sha256"]
    assert "must-not-leak" not in str(payload)
    assert raw_client.get("/api/v1/integrity/audit", headers=ADMIN_HEADERS).json()["valid"] is True
