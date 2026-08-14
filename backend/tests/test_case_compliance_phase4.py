from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

DB_PATH = Path("/tmp") / f"redpath-phase4-cases-{uuid4().hex}.db"
settings = Settings(
    database_url=f"sqlite:///{DB_PATH}",
    audit_log_path=f"/tmp/redpath-phase4-cases-{uuid4().hex}.jsonl",
    auth_bootstrap_token="phase4-cases-bootstrap-token",
    rate_limit_requests_per_minute=300,
)
raw_client = TestClient(create_app(settings))
bootstrap = raw_client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "phase4-alpha",
        "tenant_name": "Phase 4 Alpha",
        "username": "phase4-admin",
        "password": "phase4-admin-password",
    },
)
assert bootstrap.status_code == 201
ADMIN_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def login(username: str, password: str, tenant_slug: str = "phase4-alpha") -> dict[str, str]:
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
            "name": f"Phase 4 case {uuid4().hex[:8]}",
            "objective": "Validate bounded case reliability and compliance workflows.",
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
            "source": "lab/fixtures/compliance.json",
            "title": "Phase 4 evidence",
            "sha256": "d" * 64,
            "technique_id": "T1558.003",
            "notes": "metadata only; token=redact-me",
        },
    )
    assert response.status_code == 201
    return response.json()


def accept_and_verify(evidence: dict) -> None:
    reviewed = raw_client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        headers=ADMIN_HEADERS,
        json={"review_status": "accepted", "notes": "Review complete."},
    )
    assert reviewed.status_code == 200
    custody = raw_client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/custody",
        headers=ADMIN_HEADERS,
        json={"decision": "verified", "manifest_sha256": evidence["manifest_sha256"]},
    )
    assert custody.status_code == 201


def create_remediation(case_id: str, due_date: str | None = None) -> dict:
    response = raw_client.post(
        "/api/v1/remediations",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case_id,
            "finding_title": "Phase 4 remediation",
            "technique_id": "T1558.003",
            "recommendation": "Apply a bounded defensive control and validate it with evidence.",
            "owner": "phase4-team",
            "assigned_to": "phase4-admin",
            "priority": "high",
            "due_date": due_date,
        },
    )
    assert response.status_code == 201
    return response.json()


def test_sla_clock_and_mock_escalation_drafts_are_bounded() -> None:
    case = create_case()
    remediation = create_remediation(case["campaign_id"], (date.today() - timedelta(days=1)).isoformat())

    sla = raw_client.get("/api/v1/remediations/sla", headers=ADMIN_HEADERS)
    assert sla.status_code == 200
    item = next(row for row in sla.json() if row["remediation_id"] == remediation["remediation_id"])
    assert item["state"] == "overdue"
    assert item["clock"]["policy_version"] == "2.0"
    assert item["clock"]["remaining_seconds"] < 0
    assert item["clock"]["paused_seconds"] == 0

    escalations = raw_client.get("/api/v1/remediations/escalations", headers=ADMIN_HEADERS)
    assert escalations.status_code == 200
    escalation = next(row for row in escalations.json() if row["remediation_id"] == remediation["remediation_id"])
    assert escalation["policy_version"] == "2.0"
    assert escalation["notification_mode"] == "mock"
    assert escalation["requires_opt_in"] is True

    drafts = raw_client.get("/api/v1/remediations/escalation-drafts", headers=ADMIN_HEADERS)
    assert drafts.status_code == 200
    draft = next(row for row in drafts.json() if row["remediation_id"] == remediation["remediation_id"])
    assert draft["draft_id"] == escalation["draft_id"]
    assert draft["sent"] is False
    assert draft["notification_mode"] == "mock"


def test_verification_evidence_timeline_and_export_fixture_integrity() -> None:
    case = create_case()
    evidence = create_evidence(case["campaign_id"])
    accept_and_verify(evidence)
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

    verification_evidence = raw_client.post(
        f"/api/v1/remediations/{remediation['remediation_id']}/verification-evidence",
        headers=ADMIN_HEADERS,
        json={
            "evidence_id": evidence["evidence_id"],
            "manifest_sha256": evidence["manifest_sha256"],
            "summary": "Independent evidence supports remediation verification.",
        },
    )
    assert verification_evidence.status_code == 201
    assert verification_evidence.json()["recorded_by"] == "phase4-admin"

    listed = raw_client.get(
        f"/api/v1/remediations/{remediation['remediation_id']}/verification-evidence",
        headers=ADMIN_HEADERS,
    )
    assert listed.status_code == 200
    assert listed.json()[0]["manifest_sha256"] == evidence["manifest_sha256"]

    verified = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/verification",
        headers=ADMIN_HEADERS,
        json={"decision": "verified", "note": "Verification evidence reviewed."},
    )
    assert verified.status_code == 200

    timeline = raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/decision-timeline",
        headers=ADMIN_HEADERS,
    )
    assert timeline.status_code == 200
    assert timeline.json()["integrity_valid"] is True
    assert timeline.json()["events"]
    assert timeline.json()["events"][-1]["digest"] == timeline.json()["tail_digest"]

    export = raw_client.get(f"/api/v1/cases/{case['campaign_id']}/export", headers=ADMIN_HEADERS)
    assert export.status_code == 200
    export_payload = export.json()
    assert export_payload["timeline_integrity"] is True
    assert export_payload["verification_evidence"]
    assert export_payload["decision_timeline"]
    assert "redact-me" not in str(export_payload)

    fixture = raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/export-fixture",
        headers=ADMIN_HEADERS,
    )
    assert fixture.status_code == 200
    fixture_payload = fixture.json()
    assert fixture_payload["redacted"] is True
    assert fixture_payload["timeline_integrity"] is True
    assert fixture_payload["fixture_sha256"]


def test_approval_delegation_is_bounded_role_and_case_scoped() -> None:
    analyst = raw_client.post(
        "/api/v1/auth/users",
        headers=ADMIN_HEADERS,
        json={"username": "phase4-analyst", "password": "phase4-analyst-password", "roles": ["analyst"]},
    )
    assert analyst.status_code == 201
    viewer = raw_client.post(
        "/api/v1/auth/users",
        headers=ADMIN_HEADERS,
        json={"username": "phase4-viewer", "password": "phase4-viewer-password", "roles": ["viewer"]},
    )
    assert viewer.status_code == 201
    case = create_case()

    too_long = raw_client.post(
        "/api/v1/approval-delegations",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "delegate_username": "phase4-analyst",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=8)).isoformat(),
        },
    )
    assert too_long.status_code == 409

    viewer_delegation = raw_client.post(
        "/api/v1/approval-delegations",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "delegate_username": "phase4-viewer",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
        },
    )
    assert viewer_delegation.status_code == 409

    delegation = raw_client.post(
        "/api/v1/approval-delegations",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "delegate_username": "phase4-analyst",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
        },
    )
    assert delegation.status_code == 201
    delegation_id = delegation.json()["delegation_id"]

    acceptance = raw_client.post(
        "/api/v1/risk-acceptances",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "finding_title": "Delegated approval fixture",
            "rationale": "A bounded approval is delegated for a short compliance review window.",
            "expires_on": (date.today() + timedelta(days=30)).isoformat(),
        },
    )
    assert acceptance.status_code == 201
    analyst_headers = login("phase4-analyst", "phase4-analyst-password")
    approved = raw_client.patch(
        f"/api/v1/risk-acceptances/{acceptance.json()['acceptance_id']}/decision",
        headers=analyst_headers,
        json={
            "decision": "approve",
            "delegation_id": delegation_id,
            "expires_on": (date.today() + timedelta(days=15)).isoformat(),
        },
    )
    assert approved.status_code == 200
    assert approved.json()["delegated_from"] == "phase4-admin"
    assert approved.json()["delegation_id"] == delegation_id

    revoked = raw_client.post(
        f"/api/v1/approval-delegations/{delegation_id}/revoke",
        headers=ADMIN_HEADERS,
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_expiry_reminders_are_tenant_scoped_and_opt_in() -> None:
    case = create_case()
    acceptance = raw_client.post(
        "/api/v1/risk-acceptances",
        headers=ADMIN_HEADERS,
        json={
            "campaign_id": case["campaign_id"],
            "finding_title": "Expiring policy fixture",
            "rationale": "A short-lived policy exception requires an explicit reminder before expiry.",
            "expires_on": (date.today() + timedelta(days=3)).isoformat(),
        },
    )
    assert acceptance.status_code == 201

    reminders = raw_client.get("/api/v1/risk-acceptances/expiry-reminders", headers=ADMIN_HEADERS)
    assert reminders.status_code == 200
    reminder = next(row for row in reminders.json() if row["acceptance_id"] == acceptance.json()["acceptance_id"])
    assert reminder["days_remaining"] <= 14
    assert reminder["notification_mode"] == "mock"
    assert reminder["requires_opt_in"] is True
    assert reminder["sent"] is False

    tenant = raw_client.post(
        "/api/v1/auth/tenants",
        headers=ADMIN_HEADERS,
        json={
            "slug": "phase4-bravo",
            "name": "Phase 4 Bravo",
            "admin_username": "phase4-bravo-admin",
            "admin_password": "phase4-bravo-password",
        },
    )
    assert tenant.status_code == 201
    bravo_headers = login("phase4-bravo-admin", "phase4-bravo-password", "phase4-bravo")
    bravo_reminders = raw_client.get("/api/v1/risk-acceptances/expiry-reminders", headers=bravo_headers)
    assert bravo_reminders.status_code == 200
    assert all(row["tenant_id"] != reminder["tenant_id"] for row in bravo_reminders.json())
