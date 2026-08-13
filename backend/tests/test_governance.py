from app.main import app
from fastapi.testclient import TestClient

AUTH_HEADERS = {"Authorization": "Bearer test-token", "X-RedPath-Actor": "governance-test"}


def _campaign(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/campaigns",
        headers=AUTH_HEADERS,
        json={
            "name": "AI-08 Governance Case",
            "objective": "Exercise auditable case, evidence, and remediation governance workflows.",
        },
    )
    assert response.status_code == 201
    return response.json()


def _evidence(client: TestClient, campaign_id: str, technique_id: str = "T1558.003") -> dict:
    response = client.post(
        "/api/v1/evidence",
        headers=AUTH_HEADERS,
        json={
            "campaign_id": campaign_id,
            "evidence_type": "fixture",
            "source": "lab/fixtures/governance.json",
            "title": "Governance verification evidence",
            "sha256": "d" * 64,
            "technique_id": technique_id,
        },
    )
    assert response.status_code == 201
    return response.json()


def test_governance_reads_require_bearer_authentication() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/campaigns")
    assert response.status_code == 401


def test_evidence_provenance_and_review_transitions_are_strict() -> None:
    client = TestClient(app, headers=AUTH_HEADERS)
    campaign = _campaign(client)
    invalid = client.post(
        "/api/v1/evidence",
        json={
            "campaign_id": campaign["campaign_id"],
            "evidence_type": "fixture",
            "source": "lab/fixtures/governance.json",
            "title": "Malformed evidence digest",
            "sha256": "not-a-sha256",
        },
    )
    assert invalid.status_code == 422

    evidence = _evidence(client, campaign["campaign_id"])
    accepted = client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        json={"review_status": "accepted", "reviewer": "soc-lead", "notes": "Verified fixture digest."},
    )
    assert accepted.status_code == 200
    invalid_transition = client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        json={"review_status": "rejected", "reviewer": "soc-lead"},
    )
    assert invalid_transition.status_code == 409


def test_remediation_resolution_requires_accepted_verification_evidence() -> None:
    client = TestClient(app, headers=AUTH_HEADERS)
    campaign = _campaign(client)
    remediation = client.post(
        "/api/v1/remediations",
        json={
            "campaign_id": campaign["campaign_id"],
            "finding_title": "Verification-gated remediation",
            "technique_id": "T1558.003",
            "recommendation": "Preserve a verified regression fixture before closure.",
            "owner": "soc-engineering",
            "priority": "high",
        },
    ).json()
    no_verification = client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        json={"status": "resolved", "actor": "soc-engineering"},
    )
    assert no_verification.status_code == 409

    started = client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        json={"status": "in_progress", "actor": "soc-engineering"},
    )
    assert started.status_code == 200

    evidence = _evidence(client, campaign["campaign_id"])
    review = client.patch(
        f"/api/v1/evidence/{evidence['evidence_id']}/review",
        json={"review_status": "accepted", "reviewer": "soc-lead"},
    )
    assert review.status_code == 200
    resolved = client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        json={
            "status": "resolved",
            "actor": "soc-engineering",
            "verification_evidence_id": evidence["evidence_id"],
        },
    )
    assert resolved.status_code == 200
    assert resolved.json()["verification_evidence_id"] == evidence["evidence_id"]

    closed = client.patch(
        f"/api/v1/remediations/{remediation['remediation_id']}/lifecycle",
        json={"status": "closed", "actor": "soc-lead"},
    )
    assert closed.status_code == 200


def test_case_lifecycle_records_controlled_transition() -> None:
    client = TestClient(app, headers=AUTH_HEADERS)
    campaign = _campaign(client)
    closed = client.patch(
        f"/api/v1/campaigns/{campaign['campaign_id']}/lifecycle",
        json={"status": "closed", "actor": "soc-lead", "note": "Review complete."},
    )
    assert closed.status_code == 200
    archived = client.patch(
        f"/api/v1/campaigns/{campaign['campaign_id']}/lifecycle",
        json={"status": "archived", "actor": "soc-lead"},
    )
    assert archived.status_code == 200
    invalid = client.patch(
        f"/api/v1/campaigns/{campaign['campaign_id']}/lifecycle",
        json={"status": "active", "actor": "soc-lead"},
    )
    assert invalid.status_code == 409
