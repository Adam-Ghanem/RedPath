from __future__ import annotations

import hashlib
import ipaddress
import struct
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.db.models import EvidenceItem, PcapAnalysis, utcnow
from app.schemas.pcap import PcapAnalysisResponse, PcapAnalysisSummary, PcapEndpoint, PcapObservation

SessionFactory = Callable[[], Any]

PCAP_MAGIC_CONFIG: dict[bytes, tuple[str, str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", "pcap", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", "pcap", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", "pcap", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", "pcap", 1_000_000_000),
}
MAX_ENDPOINTS = 100
MAX_DNS_QUERIES = 500
MAX_OBSERVATIONS = 1_000


class PcapFormatError(ValueError):
    pass


def _safe_timestamp(seconds: int, fraction: int, divisor: int) -> datetime:
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(
            microseconds=fraction * 1_000_000 // divisor
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise PcapFormatError("packet timestamp is outside the supported UTC range") from exc


def _decode_dns_name(payload: bytes, offset: int) -> str | None:
    labels: list[str] = []
    cursor = offset
    visited: set[int] = set()
    while cursor < len(payload):
        length = payload[cursor]
        cursor += 1
        if length == 0:
            return ".".join(labels) if labels else None
        if length & 0xC0:
            if cursor >= len(payload):
                return None
            pointer = ((length & 0x3F) << 8) | payload[cursor]
            if pointer in visited or pointer >= len(payload):
                return None
            visited.add(pointer)
            pointed = _decode_dns_name(payload, pointer)
            if pointed:
                labels.append(pointed)
            return ".".join(labels) if labels else None
        if length > 63 or cursor + length > len(payload):
            return None
        label = payload[cursor : cursor + length]
        cursor += length
        try:
            decoded = label.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not decoded or any(ord(char) < 33 or ord(char) > 126 for char in decoded):
            return None
        labels.append(decoded.lower())
    return None


def _extract_dns_query(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    flags = struct.unpack_from("!H", payload, 2)[0]
    question_count = struct.unpack_from("!H", payload, 4)[0]
    if flags & 0x8000 or question_count < 1:
        return None
    return _decode_dns_name(payload, 12)


def _packet_network_payload(packet: bytes, link_type: int) -> tuple[int, bytes] | None:
    if link_type == 1:  # Ethernet II; VLAN tags are skipped safely.
        if len(packet) < 14:
            return None
        ether_type = struct.unpack_from("!H", packet, 12)[0]
        offset = 14
        while ether_type in {0x8100, 0x88A8, 0x9100} and len(packet) >= offset + 4:
            ether_type = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += 4
        return ether_type, packet[offset:]
    if link_type in {101, 228}:  # raw IPv4/IPv6 packet captures.
        if not packet:
            return None
        version = packet[0] >> 4
        return (0x0800 if version == 4 else 0x86DD if version == 6 else 0), packet
    return None


def _parse_network_packet(
    packet: bytes, link_type: int, timestamp: datetime
) -> tuple[PcapObservation | None, str | None]:
    network = _packet_network_payload(packet, link_type)
    if network is None:
        return None, None
    ether_type, payload = network
    if ether_type == 0x0800:
        if len(payload) < 20:
            return None, None
        version_ihl = payload[0]
        if version_ihl >> 4 != 4:
            return None, None
        header_length = (version_ihl & 0x0F) * 4
        if header_length < 20 or len(payload) < header_length:
            return None, None
        source_ip = str(ipaddress.ip_address(payload[12:16]))
        destination_ip = str(ipaddress.ip_address(payload[16:20]))
        protocol_number = payload[9]
        transport = payload[header_length:]
    elif ether_type == 0x86DD:
        if len(payload) < 40 or payload[0] >> 4 != 6:
            return None, None
        source_ip = str(ipaddress.ip_address(payload[8:24]))
        destination_ip = str(ipaddress.ip_address(payload[24:40]))
        protocol_number = payload[6]
        transport = payload[40:]
    else:
        return None, None

    protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}.get(protocol_number, "other")
    source_port: int | None = None
    destination_port: int | None = None
    application_payload = b""
    if protocol in {"tcp", "udp"}:
        header_length = 20 if protocol == "tcp" else 8
        if len(transport) < header_length:
            return None, None
        source_port, destination_port = struct.unpack_from("!HH", transport, 0)
        if protocol == "tcp":
            tcp_header_length = ((transport[12] >> 4) & 0x0F) * 4
            if tcp_header_length < 20 or len(transport) < tcp_header_length:
                return None, None
            application_payload = transport[tcp_header_length:]
        else:
            application_payload = transport[8:]

    observation_type = "flow"
    attributes: dict[str, Any] = {"captured_bytes": len(packet)}
    dns_query: str | None = None
    if protocol == "udp" and (source_port == 53 or destination_port == 53):
        dns_query = _extract_dns_query(application_payload)
        if dns_query:
            observation_type = "dns_query"
            attributes["query"] = dns_query
    if protocol == "tcp" and destination_port in {80, 8000, 8080} and application_payload:
        first_line = application_payload.split(b"\r\n", 1)[0][:128]
        try:
            request_line = first_line.decode("ascii")
        except UnicodeDecodeError:
            request_line = ""
        if request_line.startswith(("GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ")):
            observation_type = "http_request"
            method, _, target = request_line.partition(" ")
            attributes.update({"method": method, "target": target.rsplit(" ", 1)[0] if " " in target else target})

    observation = PcapObservation(
        timestamp_utc=timestamp,
        observation_type=observation_type,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        attributes=attributes,
    )
    return observation, dns_query


def _iter_pcap_packets(data: bytes) -> tuple[str, list[tuple[datetime, bytes, int]], list[str]]:
    magic = data[:4]
    if magic not in PCAP_MAGIC_CONFIG:
        raise PcapFormatError("unsupported capture format; expected classic PCAP or PCAP-NG")
    endian, capture_format, divisor = PCAP_MAGIC_CONFIG[magic]
    if len(data) < 24:
        raise PcapFormatError("truncated PCAP global header")
    link_type = struct.unpack_from(f"{endian}I", data, 20)[0]
    packets: list[tuple[datetime, bytes, int]] = []
    warnings: list[str] = []
    cursor = 24
    while cursor < len(data):
        if len(data) - cursor < 16:
            raise PcapFormatError("truncated PCAP packet header")
        seconds, fraction, captured_length, _original_length = struct.unpack_from(f"{endian}IIII", data, cursor)
        cursor += 16
        if captured_length > len(data) - cursor:
            raise PcapFormatError("PCAP packet length exceeds the supplied evidence")
        packet = data[cursor : cursor + captured_length]
        cursor += captured_length
        packets.append((_safe_timestamp(seconds, fraction, divisor), packet, link_type))
    if link_type not in {1, 101, 228}:
        warnings.append(f"link-layer type {link_type} is not decoded; packet counts and hashes remain valid")
    return capture_format, packets, warnings


def _iter_pcapng_packets(data: bytes) -> tuple[str, list[tuple[datetime, bytes, int]], list[str]]:
    if len(data) < 12 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise PcapFormatError("truncated PCAP-NG section header")
    byte_order_magic = data[8:12]
    if byte_order_magic == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise PcapFormatError("unsupported PCAP-NG byte order")

    packets: list[tuple[datetime, bytes, int]] = []
    warnings: list[str] = []
    interfaces: dict[int, int] = {}
    cursor = 0
    while cursor < len(data):
        if len(data) - cursor < 12:
            raise PcapFormatError("truncated PCAP-NG block header")
        block_type, block_length = struct.unpack_from(f"{endian}II", data, cursor)
        if block_length < 12 or block_length % 4 or block_length > len(data) - cursor:
            raise PcapFormatError("invalid PCAP-NG block length")
        block = data[cursor : cursor + block_length]
        trailing_length = struct.unpack_from(f"{endian}I", block, block_length - 4)[0]
        if trailing_length != block_length:
            raise PcapFormatError("PCAP-NG block length trailer mismatch")
        body = block[8:-4]
        if block_type == 0x00000001 and len(body) >= 8:
            interface_id = len(interfaces)
            link_type = struct.unpack_from(f"{endian}H", body, 0)[0]
            interfaces[interface_id] = link_type
            if link_type not in {1, 101, 228}:
                warnings.append(f"interface {interface_id} link-layer type {link_type} is not decoded")
        elif block_type == 0x00000006 and len(body) >= 20:
            interface_id, timestamp_high, timestamp_low, captured_length, _original_length = struct.unpack_from(
                f"{endian}IIIII", body, 0
            )
            packet_start = 20
            if captured_length > len(body) - packet_start:
                raise PcapFormatError("PCAP-NG packet length exceeds the supplied evidence")
            packet = body[packet_start : packet_start + captured_length]
            raw_timestamp = (timestamp_high << 32) | timestamp_low
            timestamp = _safe_timestamp(raw_timestamp // 1_000_000, raw_timestamp % 1_000_000, 1_000_000)
            packets.append((timestamp, packet, interfaces.get(interface_id, 1)))
        cursor += block_length
    if not packets and not interfaces:
        warnings.append("capture contains no decoded packet blocks")
    return "pcapng", packets, warnings


def analyze_pcap(data: bytes, file_name: str) -> dict[str, Any]:
    if not data:
        raise PcapFormatError("empty evidence is not a PCAP capture")
    sha256 = hashlib.sha256(data).hexdigest()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        capture_format, packets, warnings = _iter_pcapng_packets(data)
    else:
        capture_format, packets, warnings = _iter_pcap_packets(data)

    protocol_counts: Counter[str] = Counter()
    endpoint_counts: defaultdict[str, list[int]] = defaultdict(lambda: [0, 0])
    dns_queries: list[str] = []
    observations: list[PcapObservation] = []
    for timestamp, packet, link_type in packets:
        observation, dns_query = _parse_network_packet(packet, link_type, timestamp)
        if observation is None:
            continue
        protocol_counts[observation.protocol] += 1
        for address in (observation.source_ip, observation.destination_ip):
            if address:
                endpoint_counts[address][0] += 1
                endpoint_counts[address][1] += len(packet)
        if dns_query and dns_query not in dns_queries and len(dns_queries) < MAX_DNS_QUERIES:
            dns_queries.append(dns_query)
        if len(observations) < MAX_OBSERVATIONS:
            observations.append(observation)
    if len(packets) > MAX_OBSERVATIONS:
        warnings.append(f"observations capped at {MAX_OBSERVATIONS}; packet count remains complete")
    if packets and not observations:
        warnings.append("packets were counted but no supported network-layer observations were decoded")

    first_packet_at = min((packet[0] for packet in packets), default=None)
    last_packet_at = max((packet[0] for packet in packets), default=None)
    endpoints = [
        PcapEndpoint(ip=address, packet_count=counts[0], byte_count=counts[1])
        for address, counts in sorted(endpoint_counts.items(), key=lambda item: (-item[1][0], item[0]))[:MAX_ENDPOINTS]
    ]
    return {
        "file_name": file_name,
        "sha256": sha256,
        "file_size": len(data),
        "capture_format": capture_format,
        "packet_count": len(packets),
        "first_packet_at": first_packet_at,
        "last_packet_at": last_packet_at,
        "protocol_counts": dict(protocol_counts),
        "endpoints": [endpoint.model_dump(mode="json") for endpoint in endpoints],
        "dns_queries": dns_queries,
        "observations": [observation.model_dump(mode="json") for observation in observations],
        "warnings": warnings,
    }


def register_pcap_analysis(
    data: bytes,
    file_name: str,
    tenant_id: str,
    campaign_id: str | None,
    session_factory: SessionFactory,
) -> PcapAnalysisResponse:
    analysis = analyze_pcap(data, file_name)
    analysis_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    created_at = utcnow()
    with session_factory() as session:
        if campaign_id:
            from app.db.models import Campaign

            if session.get(Campaign, campaign_id) is None:
                raise KeyError(f"Unknown campaign: {campaign_id}")
        session.add(
            EvidenceItem(
                id=evidence_id,
                campaign_id=campaign_id,
                evidence_type="pcap",
                source="offline-upload",
                title=file_name,
                sha256=analysis["sha256"],
                notes="Offline PCAP analysis; raw capture bytes are not persisted by this vertical slice.",
            )
        )
        session.add(
            PcapAnalysis(
                id=analysis_id,
                tenant_id=tenant_id,
                evidence_id=evidence_id,
                campaign_id=campaign_id,
                created_at=created_at,
                **analysis,
            )
        )
        session.commit()
    return PcapAnalysisResponse(
        analysis_id=analysis_id,
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        created_at=created_at,
        **analysis,
    )


def list_pcap_analyses(tenant_id: str, session_factory: SessionFactory, limit: int = 20) -> list[PcapAnalysisSummary]:
    with session_factory() as session:
        rows = (
            session.query(PcapAnalysis)
            .filter_by(tenant_id=tenant_id)
            .order_by(PcapAnalysis.created_at.desc())
            .limit(max(1, min(limit, 100)))
            .all()
        )
    return [
        PcapAnalysisSummary(
            analysis_id=row.id,
            tenant_id=row.tenant_id,
            evidence_id=row.evidence_id,
            file_name=row.file_name,
            sha256=row.sha256,
            capture_format=row.capture_format,
            packet_count=row.packet_count,
            created_at=row.created_at,
        )
        for row in rows
    ]


def get_pcap_analysis(analysis_id: str, tenant_id: str, session_factory: SessionFactory) -> PcapAnalysisResponse:
    with session_factory() as session:
        row = session.query(PcapAnalysis).filter_by(id=analysis_id, tenant_id=tenant_id).one_or_none()
    if row is None:
        raise KeyError(f"Unknown PCAP analysis: {analysis_id}")
    return PcapAnalysisResponse(
        schema_version="1.0",
        analysis_id=row.id,
        evidence_id=row.evidence_id,
        tenant_id=row.tenant_id,
        campaign_id=row.campaign_id,
        file_name=row.file_name,
        sha256=row.sha256,
        file_size=row.file_size,
        capture_format=row.capture_format,
        packet_count=row.packet_count,
        first_packet_at=row.first_packet_at,
        last_packet_at=row.last_packet_at,
        protocol_counts=row.protocol_counts,
        endpoints=[PcapEndpoint.model_validate(item) for item in row.endpoints],
        dns_queries=row.dns_queries,
        observations=[PcapObservation.model_validate(item) for item in row.observations],
        warnings=row.warnings,
        created_at=row.created_at,
    )
