# Offline PCAP forensics and evidence pipeline

AI-04 adds a read-only, offline PCAP analysis slice to RedPath. The upload is parsed from memory, hashed before analysis, converted into bounded normalized observations, linked to the existing `evidence_items` workflow, and persisted as tenant-scoped metadata. The raw capture bytes are not retained by this slice.

## Safety and trust boundaries

The module never opens a socket, resolves a hostname, executes a command, or sends capture content to an external service. It accepts only files whose names end in `.pcap` or `.pcapng`, enforces the configured `PCAP_MAX_UPLOAD_BYTES` limit (50 MiB by default), rejects unsafe path components, and computes SHA-256 over the exact uploaded bytes. The parser has hard limits of 1,000 retained observations, 500 distinct DNS names, and 100 endpoints; packet counts and the original hash remain complete when normalized observations are capped.

PCAP analysis and retrieval require the `soc_analyst` or `incident_commander` role contract plus an `X-Tenant-ID` header. The current prototype exposes that contract through headers because the repository’s broader identity middleware is still being evolved by AI-02. Production deployment must bind these headers to a verified authenticated principal and server-side tenant claims; clients must not be allowed to self-assert them.

> The endpoint is an evidence-plane operation. It does not perform discovery or any active network action, and it does not store credentials, payload content, or raw packet bytes.

## API contract

| Method | Endpoint | Purpose | Required controls |
| --- | --- | --- | --- |
| POST | `/api/v1/pcap/analyses` | Upload and analyze one offline capture | `X-RedPath-Role`, `X-Tenant-ID`, multipart file, optional `campaign_id` |
| GET | `/api/v1/pcap/analyses` | List recent analyses for one tenant | `X-RedPath-Role`, `X-Tenant-ID`; `limit` is clamped to 1–100 |
| GET | `/api/v1/pcap/analyses/{analysis_id}` | Retrieve one normalized analysis | `X-RedPath-Role`, `X-Tenant-ID`; tenant is part of the query predicate |

A successful analysis returns `schema_version: "1.0"`, an `analysis_id`, an `evidence_id`, the original `sha256`, capture format, packet count, normalized protocol counts, bounded endpoint statistics, DNS query names, supported observations, timestamps, and warnings. The associated evidence record uses `evidence_type: "pcap"`, `source: "offline-upload"`, and the same SHA-256 digest, allowing it to participate in existing review, campaign timeline, manifest, and export workflows.

Example request:

```bash
curl -X POST http://localhost:8000/api/v1/pcap/analyses \
  -H 'X-RedPath-Role: soc_analyst' \
  -H 'X-Tenant-ID: lab-tenant' \
  -F 'file=@authorized-capture.pcap' \
  -F 'campaign_id=campaign-id-if-known'
```

The current parser decodes classic PCAP and the common PCAP-NG enhanced packet block form for Ethernet, raw IPv4, and raw IPv6 link layers. It extracts IPv4/IPv6 endpoints, TCP/UDP/ICMP protocol counts, DNS question names, and clearly recognizable plaintext HTTP request lines. Unsupported link-layer types and packets that cannot be safely decoded remain counted and produce warnings rather than being guessed.

## Evidence lifecycle

The service computes the SHA-256 digest before parsing. It then validates the packet framing, normalizes observations, creates an `EvidenceItem`, and creates a `PcapAnalysis` row in one database transaction. A chained audit event records the analysis identifier, evidence identifier, tenant, digest, and packet count. Failed format validation is also audited with a bounded reason string. Only normalized metadata is persisted, so the evidence manifest can prove the analyzed source without turning the RedPath database into a raw-packet archive.

The migration is `backend/migrations/001_pcap_analyses.sql`. SQLAlchemy metadata creation remains compatible with the prototype’s existing bootstrap, while the migration documents the forward-only production schema change. Tenant filtering is enforced in both list and detail queries; a valid analysis ID from another tenant returns HTTP 404 rather than disclosing its existence.

## Test coverage and limitations

`backend/tests/test_pcap.py` covers deterministic hash verification, DNS extraction, endpoint aggregation, truncated-input rejection, role gating, upload-size limits, persistence, and cross-tenant isolation. The slice intentionally does not attempt TLS decryption, file carving, payload replay, exploit detection, arbitrary BPF filtering, live capture, external enrichment, or full protocol dissection. Those capabilities require separate review, resource budgets, and explicit contracts; they are not implied by this module.
