from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient

DB_PATH = Path("/tmp") / f"redpath-phase2-{uuid4().hex}.db"
settings = Settings(
    database_url=f"sqlite:///{DB_PATH}",
    audit_log_path=f"/tmp/redpath-phase2-{uuid4().hex}.jsonl",
    auth_bootstrap_token="phase2-bootstrap-token",
    rate_limit_requests_per_minute=240,
)
raw_client = TestClient(create_app(settings))
bootstrap = raw_client.post(
    "/api/v1/auth/bootstrap",
    json={
        "bootstrap_token": settings.auth_bootstrap_token,
        "tenant_slug": "phase2-alpha",
        "tenant_name": "Phase 2 Alpha",
        "username": "phase2-admin",
        "password": "phase2-admin-password",
    },
)
assert bootstrap.status_code == 201
ALPHA_HEADERS = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def login(tenant_slug: str, username: str, password: str) -> dict[str, str]:
    response = raw_client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": tenant_slug, "username": username, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_case(headers: dict[str, str]) -> dict:
    response = raw_client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "name": f"Phase 2 case {uuid4().hex[:8]}",
            "objective": "Validate server-derived governance controls in the authorized lab.",
            "scope_snapshot": ["192.168.56.0/24"],
        },
    )
    assert response.status_code == 201
    return response.json()


def create_evidence(headers: dict[str, str], campaign_id: str, notes: str = "") -> dict:
    response = raw_client.post(
        "/api/v1/evidence",
        headers=headers,
        json={
            "campaign_id": campaign_id,
            "evidence_type": "synthetic_fixture",
            "source": "lab/fixtures/governance.json",
            "title": "Governance evidence",
            "sha256": "A" * 64,
            "technique_id": "T1558.003",
            "notes": notes,
        },
    )
    assert response.status_code == 201
    return response.json()


def create_remediation(headers: dict[str, str], campaign_id: str) -> dict:
    response = raw_client.post(
        "/api/v1/remediations",
        headers=headers,
        json={
            "campaign_id": campaign_id,
            "finding_title": "Synthetic governance finding",
            "technique_id": "T1558.003",
            "recommendation": "Apply the documented defensive remediation and validate a regression fixture.",
            "owner": "identity-team",
            "priority": "high",
        },
    )
    assert response.status_code == 201
    return response.json()


def test_phase2_actor_tenant_history_and_accepted_evidence_closure() -> None:
    tenant_id = raw_client.get("/api/v1/auth/me", headers=ALPHA_HEADERS).json()["tenant_id"]
    case = create_case(ALPHA_HEADERS)
    assert case["tenant_id"] == tenant_id
    assert case["owner"] == "phase2-admin"

    evidence = create_evidence(ALPHA_HEADERS, case["campaign_id"], "token=do-not-store")
    assert evidence["tenant_id"] == tenant_id
    assert evidence["sha256"] == "a" * 64
    assert evidence["manifest_sha256"]

    not_accepted = raw_client.patch(
        f"/api/v1/cases/{case['campaign_id']}/status",
        headers=ALPHA_HEADERS,
        json={"status": "closed", "note": "Close before evidence acceptance should fail."},
    )
    assert not_accepted.status_code == 409

    reviewed = raw_client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        headers=ALPHA_HEADERS,
        json={"review_status": "accepted", "notes": "reviewed password=hidden"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["reviewer"] == "phase2-admin"
    assert "[REDACTED]" in reviewed.json()["notes"]
    assert reviewed.json()["manifest_sha256"] == evidence["manifest_sha256"]
    custody = raw_client.post(
        f"/api/v1/evidence/{evidence['evidence_id']}/custody",
        headers=ALPHA_HEADERS,
        json={"decision": "verified", "manifest_sha256": evidence["manifest_sha256"]},
    )
    assert custody.status_code == 201
    assert custody.json()["actor"] == "phase2-admin"

    remediaton = create_remediation(ALPHA_HEADERS, case["campaign_id"])
    unresolved = raw_client.patch(
        f"/api/v1/cases/{case['campaign_id']}/status",
        headers=ALPHA_HEADERS,
        json={"status": "closed", "note": "Remediation is still open."},
    )
    assert unresolved.status_code == 409

    lifecycle = raw_client.patch(
        f"/api/v1/remediations/{remediaton['remediation_id']}/lifecycle",
        headers=ALPHA_HEADERS,
        json={"status": "in_progress", "note": "token=redacted"},
    )
    assert lifecycle.status_code == 200
    assert "[REDACTED]" in lifecycle.json()["recommendation"]
    resolved = raw_client.patch(
        f"/api/v1/remediations/{remediaton['remediation_id']}/lifecycle",
        headers=ALPHA_HEADERS,
        json={"status": "resolved", "note": "Validation complete."},
    )
    assert resolved.status_code == 200
    verified = raw_client.patch(
        f"/api/v1/remediations/{remediaton['remediation_id']}/verification",
        headers=ALPHA_HEADERS,
        json={"decision": "verified", "note": "Independent validation complete."},
    )
    assert verified.status_code == 200
    assert verified.json()["verification_status"] == "verified"

    closed = raw_client.patch(
        f"/api/v1/cases/{case['campaign_id']}/status",
        headers=ALPHA_HEADERS,
        json={"status": "closed", "note": "Accepted evidence and resolved remediation."},
    )
    assert closed.status_code == 200
    reopened = raw_client.patch(
        f"/api/v1/cases/{case['campaign_id']}/status",
        headers=ALPHA_HEADERS,
        json={"status": "active"},
    )
    assert reopened.status_code == 409

    history = raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/governance-history",
        headers=ALPHA_HEADERS,
    )
    assert history.status_code == 200
    events = history.json()
    assert events
    assert all(event["tenant_id"] == tenant_id for event in events)
    assert {event["actor"] for event in events} == {"phase2-admin"}
    assert {event["event_type"] for event in events} >= {
        "case.created",
        "evidence.registered",
        "evidence.reviewed",
        "remediation.created",
        "remediation.lifecycle_changed",
        "case.status_changed",
    }
    assert all("do-not-store" not in str(event) for event in events)
    assert all("redacted" not in str(event) for event in events)
    audit_events = [json.loads(line) for line in Path(settings.audit_log_path).read_text().splitlines() if line.strip()]
    assert any(
        event["operation"] == "case.status_changed"
        and event["actor"] == "phase2-admin"
        and event["details"]["tenant_id"] == tenant_id
        for event in audit_events
    )


def test_phase2_valid_transition_rejection_and_immutable_manifest() -> None:
    case = create_case(ALPHA_HEADERS)
    evidence = create_evidence(ALPHA_HEADERS, case["campaign_id"])
    manifest_before = raw_client.get(
        f"/api/v1/evidence/{evidence['evidence_id']}/manifest",
        headers=ALPHA_HEADERS,
    )
    assert manifest_before.status_code == 200
    before_payload = manifest_before.json()
    assert "review_status" not in before_payload["canonical_payload"]
    assert "notes" not in before_payload["canonical_payload"]

    accepted = raw_client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        headers=ALPHA_HEADERS,
        json={"review_status": "accepted", "notes": "Accepted fixture."},
    )
    assert accepted.status_code == 200
    invalid_evidence_transition = raw_client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        headers=ALPHA_HEADERS,
        json={"review_status": "unreviewed"},
    )
    assert invalid_evidence_transition.status_code == 409
    manifest_after = raw_client.get(
        f"/api/v1/evidence/{evidence['evidence_id']}/manifest",
        headers=ALPHA_HEADERS,
    )
    assert manifest_after.json()["manifest_sha256"] == before_payload["manifest_sha256"]

    remediation = create_remediation(ALPHA_HEADERS, case["campaign_id"])
    started = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        headers=ALPHA_HEADERS,
        json={"status": "in_progress"},
    )
    assert started.status_code == 200
    resolved = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        headers=ALPHA_HEADERS,
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200
    invalid_remediation_transition = raw_client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        headers=ALPHA_HEADERS,
        json={"status": "open"},
    )
    assert invalid_remediation_transition.status_code == 409


def test_phase2_export_and_history_are_tenant_safe() -> None:
    case = create_case(ALPHA_HEADERS)
    evidence = create_evidence(ALPHA_HEADERS, case["campaign_id"])
    accepted = raw_client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        headers=ALPHA_HEADERS,
        json={"review_status": "accepted"},
    )
    assert accepted.status_code == 200

    export = raw_client.get(f"/api/v1/cases/{case['campaign_id']}/export", headers=ALPHA_HEADERS)
    assert export.status_code == 200
    payload = export.json()
    tenant_id = raw_client.get("/api/v1/auth/me", headers=ALPHA_HEADERS).json()["tenant_id"]
    assert payload["tenant_id"] == tenant_id
    assert payload["campaign"]["tenant_id"] == tenant_id
    assert payload["evidence"][0]["tenant_id"] == tenant_id
    assert all(event["tenant_id"] == tenant_id for event in payload["governance_history"])
    assert len(payload["manifest_sha256"]) == 64

    tenant = raw_client.post(
        "/api/v1/auth/tenants",
        headers=ALPHA_HEADERS,
        json={
            "slug": "phase2-bravo",
            "name": "Phase 2 Bravo",
            "admin_username": "phase2-bravo-admin",
            "admin_password": "phase2-bravo-password",
        },
    )
    assert tenant.status_code == 201
    bravo_headers = login("phase2-bravo", "phase2-bravo-admin", "phase2-bravo-password")
    assert raw_client.get("/api/v1/cases", headers=bravo_headers).json() == []
    assert raw_client.get(f"/api/v1/cases/{case['campaign_id']}/export", headers=bravo_headers).status_code == 404
    assert raw_client.get(
        f"/api/v1/cases/{case['campaign_id']}/governance-history", headers=bravo_headers
    ).status_code == 404
    assert raw_client.post(
        "/api/v1/risk-acceptances",
        headers=bravo_headers,
        json={
            "campaign_id": case["campaign_id"],
            "finding_title": "Cross-tenant approval should fail",
            "rationale": "This request must not attach an approval to another tenant's case.",
            "expires_on": "2099-12-31",
        },
    ).status_code == 404
