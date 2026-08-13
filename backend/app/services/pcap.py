from __future__ import annotations

import hashlib
import hmac
import ipaddress
import struct
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.core.ownership import require_tenant_ids, tenant_query
from app.core.request_context import maybe_principal
from app.db.models import EvidenceItem, PcapAnalysis, utcnow
from app.schemas.contracts import EvidenceResponse
from app.schemas.pcap import (
    PcapAnalysisResponse,
    PcapAnalysisSummary,
    PcapDnsSummary,
    PcapEndpoint,
    PcapEvidenceView,
    PcapFlowSummary,
    PcapObservation,
)

SessionFactory = Callable[[], Any]

PCAP_MAGIC_CONFIG: dict[bytes, tuple[str, str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", "pcap", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", "pcap", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", "pcap", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", "pcap", 1_000_000_000),
}
DEFAULT_REDACTION_SALT = "redpath-lab-redaction-salt"
MAX_ENDPOINTS = 100
MAX_DNS_QUERIES = 500
MAX_FLOWS = 1_000
MAX_OBSERVATIONS = 1_000


class PcapFormatError(ValueError):
    pass


class PiiRedactor:
    """Pseudonymize network identifiers without persisting the originals."""

    def __init__(self, salt: str = DEFAULT_REDACTION_SALT) -> None:
        if not salt:
            raise ValueError("PCAP redaction salt must not be empty")
        self._salt = salt.encode("utf-8")
        self.redacted_fields = 0

    def _token(self, prefix: str, value: str) -> str:
        self.redacted_fields += 1
        digest = hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
        return f"{prefix}_{digest}"

    def ip(self, value: str) -> str:
        return self._token("ip", value)

    def domain(self, value: str) -> str:
        return self._token("dns", value.lower().rstrip("."))


def _redacted_endpoint(redactor: PiiRedactor, address: str, port: int | None) -> str:
    value = redactor.ip(address)
    return f"{value}:{port}" if port is not None else value


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


def analyze_pcap(
    data: bytes,
    file_name: str,
    *,
    max_packets: int = 100_000,
    max_endpoints: int = MAX_ENDPOINTS,
    max_dns_queries: int = MAX_DNS_QUERIES,
    max_flows: int = MAX_FLOWS,
    max_observations: int = MAX_OBSERVATIONS,
    redaction_salt: str = DEFAULT_REDACTION_SALT,
) -> dict[str, Any]:
    if not data:
        raise PcapFormatError("empty evidence is not a PCAP capture")
    limits = {
        "max_packets": max_packets,
        "max_endpoints": max_endpoints,
        "max_dns_queries": max_dns_queries,
        "max_flows": max_flows,
        "max_observations": max_observations,
    }
    if any(value < 1 for value in limits.values()):
        raise ValueError("PCAP parser limits must be positive")
    sha256 = hashlib.sha256(data).hexdigest()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        capture_format, packets, warnings = _iter_pcapng_packets(data)
    else:
        capture_format, packets, warnings = _iter_pcap_packets(data)
    if len(packets) > max_packets:
        packets = packets[:max_packets]
        warnings.append(f"packet count capped at {max_packets}; remaining packets were not examined")

    redactor = PiiRedactor(redaction_salt)
    protocol_counts: Counter[str] = Counter()
    endpoint_counts: defaultdict[str, list[int]] = defaultdict(lambda: [0, 0])
    dns_records: dict[str, list[Any]] = {}
    flows: dict[str, dict[str, Any]] = {}
    observations: list[PcapObservation] = []
    endpoint_limit_reached = False
    dns_limit_reached = False
    flow_limit_reached = False
    observation_limit_reached = False

    for timestamp, packet, link_type in packets:
        observation, dns_query = _parse_network_packet(packet, link_type, timestamp)
        if observation is None:
            continue
        protocol_counts[observation.protocol] += 1
        source_ip = observation.source_ip
        destination_ip = observation.destination_ip
        if source_ip:
            endpoint_counts[source_ip][0] += 1
            endpoint_counts[source_ip][1] += len(packet)
        if destination_ip:
            endpoint_counts[destination_ip][0] += 1
            endpoint_counts[destination_ip][1] += len(packet)
        if source_ip and destination_ip:
            source_port = observation.source_port
            destination_port = observation.destination_port
            flow_key = "|".join(
                str(value)
                for value in (observation.protocol, source_ip, destination_ip, source_port, destination_port)
            )
            flow = flows.get(flow_key)
            if flow is None:
                if len(flows) >= max_flows:
                    flow_limit_reached = True
                else:
                    flow = {
                        "flow_id": hmac.new(
                            redaction_salt.encode("utf-8"), flow_key.encode("utf-8"), hashlib.sha256
                        ).hexdigest()[:16],
                        "protocol": observation.protocol,
                        "source": source_ip,
                        "destination": destination_ip,
                        "source_port": source_port,
                        "destination_port": destination_port,
                        "packet_count": 0,
                        "byte_count": 0,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                    }
                    flows[flow_key] = flow
            if flow is not None:
                flow["packet_count"] += 1
                flow["byte_count"] += len(packet)
                flow["first_seen"] = min(flow["first_seen"], timestamp)
                flow["last_seen"] = max(flow["last_seen"], timestamp)
        if dns_query:
            if dns_query not in dns_records and len(dns_records) >= max_dns_queries:
                dns_limit_reached = True
            else:
                record = dns_records.setdefault(dns_query, [0, timestamp, timestamp])
                record[0] += 1
                record[1] = min(record[1], timestamp)
                record[2] = max(record[2], timestamp)
        if len(observations) >= max_observations:
            observation_limit_reached = True
        else:
            redacted_attributes = {"captured_bytes": len(packet)}
            if dns_query:
                redacted_attributes["query"] = redactor.domain(dns_query)
            observations.append(
                PcapObservation(
                    timestamp_utc=observation.timestamp_utc,
                    observation_type=observation.observation_type,
                    protocol=observation.protocol,
                    source_ip=redactor.ip(source_ip) if source_ip else None,
                    destination_ip=redactor.ip(destination_ip) if destination_ip else None,
                    source_port=observation.source_port,
                    destination_port=observation.destination_port,
                    attributes=redacted_attributes,
                )
            )

    if len(endpoint_counts) > max_endpoints:
        endpoint_limit_reached = True
    if endpoint_limit_reached:
        warnings.append(f"endpoint summary capped at {max_endpoints} records")
    if dns_limit_reached:
        warnings.append(f"DNS summary capped at {max_dns_queries} unique queries")
    if flow_limit_reached:
        warnings.append(f"flow summary capped at {max_flows} records")
    if observation_limit_reached:
        warnings.append(f"observations capped at {max_observations}; packet count remains complete")
    if packets and not observations:
        warnings.append("packets were counted but no supported network-layer observations were decoded")

    first_packet_at = min((packet[0] for packet in packets), default=None)
    last_packet_at = max((packet[0] for packet in packets), default=None)
    endpoint_rows = sorted(endpoint_counts.items(), key=lambda item: (-item[1][0], item[0]))
    endpoints = [
        PcapEndpoint(ip=redactor.ip(address), packet_count=counts[0], byte_count=counts[1])
        for address, counts in endpoint_rows[:max_endpoints]
    ]
    flow_rows = [
        PcapFlowSummary(
            flow_id=f"flow_{flow['flow_id']}",
            protocol=flow["protocol"],
            source=_redacted_endpoint(redactor, flow["source"], flow["source_port"]),
            destination=_redacted_endpoint(redactor, flow["destination"], flow["destination_port"]),
            source_port=flow["source_port"],
            destination_port=flow["destination_port"],
            packet_count=flow["packet_count"],
            byte_count=flow["byte_count"],
            first_seen=flow["first_seen"],
            last_seen=flow["last_seen"],
        )
        for flow in flows.values()
    ]
    dns_summary = [
        PcapDnsSummary(query=redactor.domain(query), count=values[0], first_seen=values[1], last_seen=values[2])
        for query, values in dns_records.items()
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
        "dns_queries": [item.query for item in dns_summary],
        "observations": [observation.model_dump(mode="json") for observation in observations],
        "redaction_mode": "pseudonymized",
        "redacted_fields": redactor.redacted_fields,
        "flow_count": len(flow_rows),
        "flows": [flow.model_dump(mode="json") for flow in flow_rows],
        "dns_summary": [item.model_dump(mode="json") for item in dns_summary],
        "warnings": warnings,
    }


def register_pcap_analysis(
    data: bytes,
    file_name: str,
    tenant_id: str,
    campaign_id: str | None,
    session_factory: SessionFactory,
    *,
    max_packets: int = 100_000,
    max_endpoints: int = MAX_ENDPOINTS,
    max_dns_queries: int = MAX_DNS_QUERIES,
    max_flows: int = MAX_FLOWS,
    max_observations: int = MAX_OBSERVATIONS,
    redaction_salt: str = DEFAULT_REDACTION_SALT,
) -> PcapAnalysisResponse:
    principal = maybe_principal()
    if principal is not None:
        require_tenant_ids(principal, tenant_id)
    analysis = analyze_pcap(
        data,
        file_name,
        max_packets=max_packets,
        max_endpoints=max_endpoints,
        max_dns_queries=max_dns_queries,
        max_flows=max_flows,
        max_observations=max_observations,
        redaction_salt=redaction_salt,
    )
    analysis_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    created_at = utcnow()
    with session_factory() as session:
        if campaign_id:
            from app.db.models import Campaign

            if session.query(Campaign).filter_by(id=campaign_id, tenant_id=tenant_id).first() is None:
                raise KeyError(f"Unknown campaign: {campaign_id}")
        session.add(
            EvidenceItem(
                id=evidence_id,
                tenant_id=tenant_id,
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


def _analysis_response(row: PcapAnalysis) -> PcapAnalysisResponse:
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
        redaction_mode=row.redaction_mode,
        redacted_fields=row.redacted_fields,
        flow_count=row.flow_count,
        flows=[PcapFlowSummary.model_validate(item) for item in row.flows],
        dns_summary=[PcapDnsSummary.model_validate(item) for item in row.dns_summary],
        created_at=row.created_at,
    )


def list_pcap_analyses(tenant_id: str, session_factory: SessionFactory, limit: int = 20) -> list[PcapAnalysisSummary]:
    with session_factory() as session:
        rows = (
            session.query(PcapAnalysis, EvidenceItem)
            .join(EvidenceItem, EvidenceItem.id == PcapAnalysis.evidence_id)
            .filter(PcapAnalysis.tenant_id == tenant_id, EvidenceItem.tenant_id == tenant_id)
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
            campaign_id=row.campaign_id,
            evidence_title=evidence.title,
            review_status=evidence.review_status,
            redaction_mode=row.redaction_mode,
            redacted_fields=row.redacted_fields,
            flow_count=row.flow_count,
            dns_count=len(row.dns_summary),
            created_at=row.created_at,
        )
        for row, evidence in rows
    ]


def get_pcap_analysis(analysis_id: str, tenant_id: str, session_factory: SessionFactory) -> PcapAnalysisResponse:
    with session_factory() as session:
        row = (
            tenant_query(session.query(PcapAnalysis), PcapAnalysis, tenant_id)
            .filter(PcapAnalysis.id == analysis_id)
            .one_or_none()
        )
    if row is None:
        raise KeyError(f"Unknown PCAP analysis: {analysis_id}")
    return _analysis_response(row)


def get_pcap_evidence_view(
    analysis_id: str, tenant_id: str, session_factory: SessionFactory
) -> PcapEvidenceView:
    with session_factory() as session:
        row = (
            session.query(PcapAnalysis, EvidenceItem)
            .join(EvidenceItem, EvidenceItem.id == PcapAnalysis.evidence_id)
            .filter(
                PcapAnalysis.id == analysis_id,
                PcapAnalysis.tenant_id == tenant_id,
                EvidenceItem.tenant_id == tenant_id,
            )
            .one_or_none()
        )
    if row is None:
        raise KeyError(f"Unknown PCAP analysis: {analysis_id}")
    analysis, evidence = row
    return PcapEvidenceView(
        evidence=EvidenceResponse(
            evidence_id=evidence.id,
            campaign_id=evidence.campaign_id,
            run_id=evidence.run_id,
            evidence_type=evidence.evidence_type,
            source=evidence.source,
            title=evidence.title,
            sha256=evidence.sha256,
            technique_id=evidence.technique_id,
            notes=evidence.notes,
            review_status=evidence.review_status,
            reviewer=evidence.reviewer,
            reviewed_at=evidence.reviewed_at,
            created_at=evidence.created_at,
        ),
        analysis=_analysis_response(analysis),
    )


def get_pcap_evidence_view_by_evidence(
    evidence_id: str, tenant_id: str, session_factory: SessionFactory
) -> PcapEvidenceView:
    with session_factory() as session:
        row = (
            session.query(PcapAnalysis, EvidenceItem)
            .join(EvidenceItem, EvidenceItem.id == PcapAnalysis.evidence_id)
            .filter(
                PcapAnalysis.evidence_id == evidence_id,
                PcapAnalysis.tenant_id == tenant_id,
                EvidenceItem.tenant_id == tenant_id,
            )
            .one_or_none()
        )
    if row is None:
        raise KeyError(f"Unknown PCAP evidence: {evidence_id}")
    analysis, evidence = row
    return PcapEvidenceView(
        evidence=EvidenceResponse(
            evidence_id=evidence.id,
            campaign_id=evidence.campaign_id,
            run_id=evidence.run_id,
            evidence_type=evidence.evidence_type,
            source=evidence.source,
            title=evidence.title,
            sha256=evidence.sha256,
            technique_id=evidence.technique_id,
            notes=evidence.notes,
            review_status=evidence.review_status,
            reviewer=evidence.reviewer,
            reviewed_at=evidence.reviewed_at,
            created_at=evidence.created_at,
        ),
        analysis=_analysis_response(analysis),
    )
