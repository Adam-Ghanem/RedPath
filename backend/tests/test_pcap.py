from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from app.api.routes import build_router
from app.core.config import Settings
from app.services.pcap import PcapFormatError, analyze_pcap
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)


def _ethernet_ipv4_udp(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    import ipaddress

    source_ip = ipaddress.ip_address(source).packed
    destination_ip = ipaddress.ip_address(destination).packed
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, source_ip, destination_ip)
    return (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800) + ip + udp)


def _pcap_fixture() -> bytes:
    frames = [
        _ethernet_ipv4_udp("192.168.56.10", "192.168.56.53", 53000, 53, _dns_query("example.test")),
        _ethernet_ipv4_udp(
            "192.168.56.53",
            "192.168.56.10",
            53,
            53000,
            b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
        ),
    ]
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packets = b"".join(
        struct.pack("<IIII", 1_700_000_000 + index, 1000, len(frame), len(frame)) + frame
        for index, frame in enumerate(frames)
    )
    return global_header + packets


def test_analyze_pcap_is_offline_and_hashes_original_bytes() -> None:
    data = _pcap_fixture()

    result = analyze_pcap(data, "capture.pcap")

    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["capture_format"] == "pcap"
    assert result["packet_count"] == 2
    assert result["protocol_counts"] == {"udp": 2}
    assert result["dns_queries"] == ["example.test"]
    assert {endpoint["ip"] for endpoint in result["endpoints"]} == {"192.168.56.10", "192.168.56.53"}
    assert all("password" not in str(observation).lower() for observation in result["observations"])


def test_analyze_pcap_rejects_truncated_evidence() -> None:
    try:
        analyze_pcap(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"\x00" * 4,
            "bad.pcap",
        )
    except PcapFormatError as exc:
        assert "truncated" in str(exc)
    else:
        raise AssertionError("truncated evidence must be rejected")


def test_pcap_api_persists_metadata_and_enforces_role_and_tenant_isolation(tmp_path: Path) -> None:
    app = FastAPI()
    app.include_router(
        build_router(
            Settings(
                database_url=f"sqlite:///{tmp_path / 'redpath.db'}",
                audit_log_path=str(tmp_path / "audit.jsonl"),
                pcap_max_upload_bytes=1024 * 1024,
            )
        )
    )
    client = TestClient(app)
    data = _pcap_fixture()

    unauthorized = client.post(
        "/api/v1/pcap/analyses",
        files={"file": ("capture.pcap", data, "application/vnd.tcpdump.pcap")},
        headers={"X-Tenant-ID": "tenant-a"},
    )
    assert unauthorized.status_code == 401

    created = client.post(
        "/api/v1/pcap/analyses",
        files={"file": ("capture.pcap", data, "application/vnd.tcpdump.pcap")},
        headers={"X-RedPath-Role": "soc_analyst", "X-Tenant-ID": "tenant-a"},
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["evidence_id"]
    assert payload["sha256"] == hashlib.sha256(data).hexdigest()
    assert payload["packet_count"] == 2

    own_list = client.get(
        "/api/v1/pcap/analyses",
        headers={"X-RedPath-Role": "soc_analyst", "X-Tenant-ID": "tenant-a"},
    )
    other_list = client.get(
        "/api/v1/pcap/analyses",
        headers={"X-RedPath-Role": "soc_analyst", "X-Tenant-ID": "tenant-b"},
    )
    assert own_list.status_code == 200
    assert len(own_list.json()) == 1
    assert other_list.status_code == 200
    assert other_list.json() == []

    cross_tenant_detail = client.get(
        f"/api/v1/pcap/analyses/{payload['analysis_id']}",
        headers={"X-RedPath-Role": "soc_analyst", "X-Tenant-ID": "tenant-b"},
    )
    assert cross_tenant_detail.status_code == 404


def test_pcap_api_rejects_oversized_and_non_capture_uploads(tmp_path: Path) -> None:
    app = FastAPI()
    app.include_router(
        build_router(
            Settings(
                database_url=f"sqlite:///{tmp_path / 'redpath.db'}",
                audit_log_path=str(tmp_path / "audit.jsonl"),
                pcap_max_upload_bytes=32,
            )
        )
    )
    client = TestClient(app)
    headers = {"X-RedPath-Role": "soc_analyst", "X-Tenant-ID": "tenant-a"}

    oversized = client.post(
        "/api/v1/pcap/analyses",
        files={"file": ("capture.pcap", b"x" * 33, "application/octet-stream")},
        headers=headers,
    )
    assert oversized.status_code == 413

    invalid = client.post(
        "/api/v1/pcap/analyses",
        files={"file": ("capture.pcap", b"not-a-capture", "application/octet-stream")},
        headers={"X-RedPath-Role": "soc_analyst", "X-Tenant-ID": "tenant-a"},
    )
    assert invalid.status_code == 422


def test_analyze_pcapng_decodes_enhanced_packet_block() -> None:
    frame = _ethernet_ipv4_udp("192.168.56.10", "192.168.56.53", 53000, 53, _dns_query("pcapng.test"))
    section_header = struct.pack(">II", 0x0A0D0D0A, 28)
    section_header += struct.pack(">IHHqI", 0x1A2B3C4D, 1, 0, -1, 28)
    interface_description = struct.pack(">IIHHII", 1, 20, 1, 0, 65535, 20)
    padded_frame = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
    raw_timestamp = 1_700_000_000_123_000
    enhanced_packet = struct.pack(
        ">IIIIIII",
        6,
        32 + len(padded_frame),
        0,
        raw_timestamp >> 32,
        raw_timestamp & 0xFFFFFFFF,
        len(frame),
        len(frame),
    )
    enhanced_packet += padded_frame + struct.pack(">I", 32 + len(padded_frame))

    result = analyze_pcap(section_header + interface_description + enhanced_packet, "capture.pcapng")

    assert result["capture_format"] == "pcapng"
    assert result["packet_count"] == 1
    assert result["dns_queries"] == ["pcapng.test"]
