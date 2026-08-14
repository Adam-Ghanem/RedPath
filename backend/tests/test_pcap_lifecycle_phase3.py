from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from app.core.config import Settings
from app.db.models import EvidenceItem, PcapAnalysis, PcapLifecycle, create_session_factory
from app.main import create_app
from app.services.pcap_lifecycle import verify_redaction
from fastapi.testclient import TestClient


def _dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)


def _udp_frame(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    source_ip = ipaddress.ip_address(source).packed
    destination_ip = ipaddress.ip_address(destination).packed
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        0,
        0,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800) + ipv4 + udp


def _benign_pcap() -> bytes:
    frame = _udp_frame("192.168.56.10", "192.168.56.53", 53000, 53, _dns_query("safe.fixture.test"))
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet = struct.pack("<IIII", 1_700_000_000, 1000, len(frame), len(frame)) + frame
    return header + packet


def _client(tmp_path: Path) -> tuple[TestClient, Settings, dict[str, str]]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'redpath.db'}",
        audit_log_path=str(tmp_path / "audit.jsonl"),
        auth_bootstrap_token="phase3-pcap-bootstrap-token",
        pcap_retention_days=90,
        pcap_quarantine_retention_days=30,
        pcap_drilldown_max_flows=1,
        pcap_drilldown_max_dns=1,
        pcap_drilldown_max_observations=1,
    )
    client = TestClient(create_app(settings))
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": settings.auth_bootstrap_token,
            "tenant_slug": "phase3-pcap",
            "tenant_name": "Phase 3 PCAP Tenant",
            "username": "phase3-admin",
            "password": "phase3-admin-password",
        },
    )
    assert bootstrap.status_code == 201, bootstrap.text
    return client, settings, {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def _upload(client: TestClient, headers: dict[str, str], data: bytes) -> dict:
    response = client.post(
        "/api/v1/pcap/analyses",
        headers=headers,
        files={"file": ("authorized-fixture.pcap", data, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_lifecycle_manifest_redaction_and_bounded_drilldown(tmp_path: Path) -> None:
    client, _settings, headers = _client(tmp_path)
    payload = _upload(client, headers, _benign_pcap())

    lifecycle = client.get(f"/api/v1/pcap/evidence/{payload['evidence_id']}/lifecycle", headers=headers)
    assert lifecycle.status_code == 200
    assert lifecycle.json()["state"] == "retained"
    assert lifecycle.json()["storage"] == {
        "storage_backend": "metadata-only",
        "storage_locator": "none",
        "raw_bytes_retained": False,
        "stored_bytes": 0,
        "source_sha256": payload["sha256"],
    }
    assert lifecycle.json()["retention_until"]

    manifest = client.get(f"/api/v1/pcap/evidence/{payload['evidence_id']}/manifest", headers=headers)
    assert manifest.status_code == 200
    assert manifest.json()["valid"] is True
    assert manifest.json()["computed_manifest_sha256"] == lifecycle.json()["manifest_sha256"]

    deletion = client.get(f"/api/v1/pcap/evidence/{payload['evidence_id']}/deletion-check", headers=headers)
    assert deletion.status_code == 200
    assert deletion.json()["allowed"] is False
    assert deletion.json()["dry_run"] is True
    assert "retention_active" in deletion.json()["blockers"]

    drilldown = client.get(f"/api/v1/pcap/analyses/{payload['analysis_id']}/drilldown", headers=headers)
    assert drilldown.status_code == 200
    drilldown_payload = drilldown.json()
    assert drilldown_payload["manifest"]["valid"] is True
    assert drilldown_payload["redaction"]["valid"] is True
    assert len(drilldown_payload["flows"]) <= 1
    assert len(drilldown_payload["dns_summary"]) <= 1
    assert len(drilldown_payload["observations"]) <= 1
    serialized = str(drilldown_payload)
    assert "192.168.56.10" not in serialized
    assert "safe.fixture.test" not in serialized
    assert "raw packet" not in serialized.lower()


def test_parse_failure_is_quarantined_with_safe_error_and_no_raw_storage(tmp_path: Path) -> None:
    client, settings, headers = _client(tmp_path)
    response = client.post(
        "/api/v1/pcap/analyses",
        headers=headers,
        files={"file": ("malformed.pcap", b"not-a-capture", "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 422
    safe_error = response.json()
    assert safe_error["detail"] == "Request failed"
    assert safe_error["error_code"] == "http_422"
    assert "not-a-capture" not in str(safe_error)

    quarantined = client.get("/api/v1/pcap/lifecycle?state=quarantined", headers=headers)
    assert quarantined.status_code == 200
    assert len(quarantined.json()) == 1
    evidence_id = quarantined.json()[0]["evidence_id"]
    lifecycle = client.get(f"/api/v1/pcap/evidence/{evidence_id}/lifecycle", headers=headers)
    assert lifecycle.status_code == 200
    assert lifecycle.json()["state"] == "quarantined"
    assert lifecycle.json()["failure_code"] == "unsupported_format"
    assert lifecycle.json()["parse_error"] == "Capture format is not supported."
    assert lifecycle.json()["storage"]["raw_bytes_retained"] is False
    assert lifecycle.json()["storage"]["stored_bytes"] == 0
    assert lifecycle.json()["storage"]["source_sha256"]

    linked = client.get(f"/api/v1/evidence/{evidence_id}/pcap", headers=headers)
    assert linked.status_code == 404
    audit_text = Path(settings.audit_log_path).read_text(encoding="utf-8")
    assert "not-a-capture" not in audit_text
    assert "pcap.quarantined" in audit_text


def test_lifecycle_and_drilldown_reject_cross_tenant_reads(tmp_path: Path) -> None:
    client, _settings, headers = _client(tmp_path)
    payload = _upload(client, headers, _benign_pcap())
    tenant = client.post(
        "/api/v1/auth/tenants",
        headers=headers,
        json={
            "slug": "phase3-other",
            "name": "Phase 3 Other",
            "admin_username": "other-admin",
            "admin_password": "other-password",
        },
    )
    assert tenant.status_code == 201
    login = client.post(
        "/api/v1/auth/token",
        json={"tenant_slug": "phase3-other", "username": "other-admin", "password": "other-password"},
    )
    assert login.status_code == 200
    other_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    for endpoint in (
        f"/api/v1/pcap/evidence/{payload['evidence_id']}/lifecycle",
        f"/api/v1/pcap/evidence/{payload['evidence_id']}/manifest",
        f"/api/v1/pcap/evidence/{payload['evidence_id']}/deletion-check",
        f"/api/v1/pcap/analyses/{payload['analysis_id']}/drilldown",
    ):
        assert client.get(endpoint, headers=other_headers).status_code == 404


def test_manifest_and_redaction_tampering_fail_closed(tmp_path: Path) -> None:
    client, settings, headers = _client(tmp_path)
    payload = _upload(client, headers, _benign_pcap())
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        evidence = session.query(EvidenceItem).filter_by(id=payload["evidence_id"]).one()
        stored_manifest = evidence.manifest_sha256
        evidence.title = "tampered-title"
        session.commit()

    manifest = client.get(f"/api/v1/pcap/evidence/{payload['evidence_id']}/manifest", headers=headers)
    assert manifest.status_code == 200
    assert manifest.json()["valid"] is False
    assert manifest.json()["failure_code"] == "manifest_mismatch"
    assert client.get(f"/api/v1/pcap/analyses/{payload['analysis_id']}/drilldown", headers=headers).status_code == 409

    with session_factory() as session:
        analysis = session.query(PcapAnalysis).filter_by(id=payload["analysis_id"]).one()
        analysis.endpoints = [{"ip": "192.168.56.10", "packet_count": 1, "byte_count": 1}]
        lifecycle = session.query(PcapLifecycle).filter_by(evidence_id=payload["evidence_id"]).one()
        lifecycle.manifest_sha256 = stored_manifest or lifecycle.manifest_sha256
        redaction_invalid = verify_redaction(analysis)
        session.commit()

    assert client.get(f"/api/v1/pcap/analyses/{payload['analysis_id']}/drilldown", headers=headers).status_code == 409
    assert redaction_invalid.valid is False


def test_expired_retention_still_blocks_legal_hold_deletion(tmp_path: Path) -> None:
    client, settings, headers = _client(tmp_path)
    payload = _upload(client, headers, _benign_pcap())
    session_factory = create_session_factory(settings.database_url)
    from datetime import timedelta

    with session_factory() as session:
        lifecycle = session.query(PcapLifecycle).filter_by(evidence_id=payload["evidence_id"]).one()
        lifecycle.retention_until = lifecycle.created_at - timedelta(days=1)
        lifecycle.legal_hold = True
        session.commit()

    deletion = client.get(f"/api/v1/pcap/evidence/{payload['evidence_id']}/deletion-check", headers=headers)
    assert deletion.status_code == 200
    assert deletion.json()["allowed"] is False
    assert deletion.json()["blockers"] == ["legal_hold"]
