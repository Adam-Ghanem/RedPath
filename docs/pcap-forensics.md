# Offline PCAP forensics and evidence pipeline

This read-only, offline PCAP analysis capability parses uploads from memory, hashes them before analysis, converts them into bounded normalized observations and pseudonymized flow/DNS summaries, links them to the existing `evidence_items` workflow, and persists tenant-scoped metadata. The raw capture bytes are not retained by this capability.

## Safety and trust boundaries

The module never opens a socket, resolves a hostname, executes a command, or sends capture content to an external service. It accepts only files whose names end in `.pcap` or `.pcapng`, enforces the configured `PCAP_MAX_UPLOAD_BYTES` limit (50 MiB by default), rejects unsafe path components, and computes SHA-256 over the exact uploaded bytes. The parser has hard limits of 100,000 examined packets, 1,000 retained observations, 1,000 flows, 500 distinct DNS names, and 100 endpoints; packet counts and the original hash remain complete when normalized summaries are capped.

PCAP upload and analysis require an authenticated bearer session with the `analyze` permission, while retrieval requires the `read` permission. The service derives tenant identity from the verified authenticated principal; clients cannot self-assert a tenant through request headers.

> The endpoint is an evidence-plane operation. It does not perform discovery or any active network action, and it does not store credentials, payload content, or raw packet bytes.

## API contract

| Method | Endpoint | Purpose | Required controls |
| --- | --- | --- | --- |
| POST | `/api/v1/pcap/analyses` | Upload and analyze one offline capture | Bearer authentication with `analyze`; multipart file; optional `campaign_id` |
| GET | `/api/v1/pcap/analyses` | List recent analyses for one tenant | Bearer authentication with `read`; `limit` is clamped to 1–100 |
| GET | `/api/v1/pcap/analyses/{analysis_id}` | Retrieve one normalized analysis | Bearer authentication with `read`; tenant is part of the query predicate |
| GET | `/api/v1/evidence/{evidence_id}/pcap` | Retrieve the linked evidence record and redacted PCAP detail | Bearer authentication with `read`; evidence and analysis must belong to the authenticated tenant |

A successful analysis returns `schema_version: "1.0"`, an `analysis_id`, an `evidence_id`, the original `sha256`, capture format, packet count, normalized protocol counts, bounded endpoint statistics, pseudonymized flow and DNS summaries, a redaction mode/count, timestamps, and warnings. IP addresses and DNS names are represented by deterministic HMAC-SHA-256 pseudonyms; raw packet payloads, HTTP targets, credentials, certificates, and file contents are not returned. The associated evidence record uses `evidence_type: "pcap"`, `source: "offline-upload"`, and the same SHA-256 digest, allowing it to participate in existing review, campaign timeline, manifest, and export workflows.

Example request:

```bash
curl -X POST http://localhost:8000/api/v1/pcap/analyses \
  -H "Authorization: Bearer $REDPATH_ACCESS_TOKEN" \
  -F 'file=@authorized-capture.pcap' \
  -F 'campaign_id=campaign-id-if-known'
```

The current parser decodes classic PCAP and the common PCAP-NG enhanced packet block form for Ethernet, raw IPv4, and raw IPv6 link layers. It extracts IPv4/IPv6 endpoint statistics, TCP/UDP/ICMP protocol counts, DNS question metadata, and transport flow metadata. Unsupported link-layer types and packets that cannot be safely decoded remain counted and produce warnings rather than being guessed.

## Evidence lifecycle

The service computes the SHA-256 digest before parsing. It then validates the packet framing, normalizes observations, creates an `EvidenceItem`, and creates a `PcapAnalysis` row in one database transaction. A chained audit event records the analysis identifier, evidence identifier, tenant, digest, and packet count. Failed format validation is also audited with a bounded reason string. Only normalized metadata is persisted, so the evidence manifest can prove the analyzed source without turning the RedPath database into a raw-packet archive.

The base migration is `backend/migrations/001_pcap_analyses.sql`; `backend/migrations/002_pcap_redacted_summaries.sql` adds the Phase 2 summary fields without rewriting the already-applied base migration. SQLAlchemy metadata creation remains compatible with the prototype’s existing bootstrap. Tenant filtering is enforced in list, analysis-detail, and linked-evidence queries; a valid analysis or evidence ID from another tenant returns HTTP 404 rather than disclosing its existence.

## Test coverage and limitations

`backend/tests/test_pcap.py` covers deterministic hash verification, pseudonymized output verification, bounded flow/DNS/observation summaries, truncated-input rejection, role gating, upload-size limits, linked evidence reads, persistence, and cross-tenant isolation. The slice intentionally does not attempt TLS decryption, file carving, payload replay, exploit detection, arbitrary BPF filtering, live capture, external enrichment, or full protocol dissection. Those capabilities require separate review, resource budgets, and explicit contracts; they are not implied by this module.
