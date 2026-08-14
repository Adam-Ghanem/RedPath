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
| GET | `/api/v1/pcap/lifecycle` | List retained or quarantined metadata records for the tenant | Bearer authentication with `read`; bounded limit and optional state filter |
| GET | `/api/v1/pcap/evidence/{evidence_id}/lifecycle` | Read retention, legal-hold, quarantine, and storage metadata | Bearer authentication with `read`; tenant-filtered |
| GET | `/api/v1/pcap/evidence/{evidence_id}/manifest` | Recompute and verify the immutable evidence manifest | Bearer authentication with `read`; returns `valid: false` on mismatch |
| GET | `/api/v1/pcap/evidence/{evidence_id}/deletion-check` | Dry-run deletion eligibility check | Bearer authentication with `read`; never mutates evidence |
| GET | `/api/v1/pcap/analyses/{analysis_id}/drilldown` | Read bounded flow, DNS, and observation details | Bearer authentication with `read`; fail-closed on manifest or redaction violation |

A successful analysis returns `schema_version: "1.0"`, an `analysis_id`, an `evidence_id`, the original `sha256`, capture format, packet count, normalized protocol counts, bounded endpoint statistics, pseudonymized flow and DNS summaries, a redaction mode/count, timestamps, and warnings. IP addresses and DNS names are represented by deterministic HMAC-SHA-256 pseudonyms; raw packet payloads, HTTP targets, credentials, certificates, and file contents are not returned. The associated evidence record uses `evidence_type: "pcap"`, `source: "offline-upload"`, and the same SHA-256 digest, allowing it to participate in existing review, campaign timeline, manifest, and export workflows.

Example request:

```bash
curl -X POST http://localhost:8000/api/v1/pcap/analyses \
  -H "Authorization: Bearer $REDPATH_ACCESS_TOKEN" \
  -F 'file=@authorized-capture.pcap' \
  -F 'campaign_id=campaign-id-if-known'
```

The current parser decodes classic PCAP and the common PCAP-NG enhanced packet block form for Ethernet, raw IPv4, and raw IPv6 link layers. It extracts IPv4/IPv6 endpoint statistics, TCP/UDP/ICMP protocol counts, DNS question metadata, and transport flow metadata. Unsupported link-layer types and packets that cannot be safely decoded remain counted and produce warnings rather than being guessed. Analyst drill-down is separately bounded to the configured flow, DNS, and observation limits.

## Evidence lifecycle

The service computes the SHA-256 digest before parsing. It then validates the packet framing, normalizes observations, creates an `EvidenceItem`, creates a `PcapAnalysis` row, and records a `retained` lifecycle row in one database transaction. The lifecycle storage abstraction is explicitly `metadata-only` with locator `none`, zero stored bytes, and `raw_bytes_retained: false`. Failed format validation creates a tenant-scoped `quarantined` lifecycle row with a safe failure code and generic error text; the raw upload is not retained. The API error envelope intentionally omits quarantine identifiers and parser details, while the authorized lifecycle list exposes bounded metadata for analyst follow-up.

Retention defaults to 90 days for successful analyses and 30 days for quarantined records. The deletion-check endpoint is dry-run only and blocks while retention is active, a legal hold exists, deletion is already pending, or the record is already deleted. No endpoint deletes evidence in this read-only phase.

Manifest verification recomputes the canonical immutable evidence payload used by the shared governance service. Redaction verification rejects raw IP addresses, unpseudonymized DNS names, unexpected payload attributes, and any non-pseudonymized mode. Drill-down returns HTTP 409 through the safe error envelope if either verification fails. Tenant predicates are applied to every lifecycle, manifest, deletion-check, and drill-down query.

The base migrations are `backend/migrations/001_pcap_analyses.sql` and `backend/migrations/002_pcap_redacted_summaries.sql`. `backend/migrations/003_pcap_evidence_lifecycle.sql` adds the lifecycle metadata table without rewriting earlier migrations. Rollback requires an approved metadata backup and lifecycle export, followed by `DROP TABLE IF EXISTS pcap_lifecycles;`; rollback removes lifecycle metadata only and must not be used as a substitute for evidence-retention approval. SQLAlchemy metadata creation remains compatible with the prototype’s bootstrap. Tenant filtering is enforced in list, detail, linked-evidence, lifecycle, manifest, deletion-check, and drill-down queries; a valid identifier from another tenant returns HTTP 404 rather than disclosing its existence.

## Test coverage and limitations

`backend/tests/test_pcap.py` covers deterministic hash verification, pseudonymized output verification, bounded flow/DNS/observation summaries, truncated-input rejection, role gating, upload-size limits, linked evidence reads, persistence, and cross-tenant isolation. `backend/tests/test_pcap_lifecycle_phase3.py` covers retention metadata, manifest verification, strict redaction verification, bounded drill-down, quarantine safe failure, lifecycle listing, legal holds, raw-byte absence, and cross-tenant lifecycle isolation. The slice intentionally does not attempt TLS decryption, file carving, payload replay, exploit detection, arbitrary BPF filtering, live capture, external enrichment, or full protocol dissection. Those capabilities require separate review, resource budgets, and explicit contracts; they are not implied by this module.
