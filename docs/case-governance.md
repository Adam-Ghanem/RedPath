# Case Governance Integration

Case governance is a tenant-scoped compatibility layer over the existing campaign, evidence, remediation, and risk-acceptance resources. The API keeps the established campaign contracts while exposing `/api/v1/cases` aliases for analysts and reporting clients.

## Identity and tenancy

Every protected case operation requires the existing bearer-session authentication and `manage_cases`, `read`, or `view_audit` permission as appropriate. The service derives `tenant_id` and actor fields from the authenticated principal. Request payloads cannot select a tenant or impersonate a reviewer, remediation lifecycle actor, case-status actor, or risk-acceptance approver.

All case, evidence, remediation, risk-acceptance, governance-history, and export queries include the server-derived tenant predicate. An identifier belonging to another tenant is treated as not found. The existing RBAC dependency chain remains authoritative; this integration does not introduce a parallel authorization system.

## Transition invariants

Evidence follows the existing state machine: `unreviewed` may move to `in_review`, `accepted`, or `rejected`; `in_review` may move to `unreviewed`, `accepted`, or `rejected`; `rejected` may return to `in_review`; and `accepted` may return to `in_review` for a documented re-review. Invalid transitions return HTTP 409 and do not create a history event.

Remediation follows the existing state machine: `open` may move to `in_progress` or `blocked`; `in_progress` may move to `open`, `blocked`, or `resolved`; `blocked` may move to `open`, `in_progress`, or `resolved`; `resolved` may move to `in_progress` or `closed`; and `closed` is terminal. Each accepted transition creates a tenant-scoped governance event with a server-derived actor.

Cases may move from `active` to `on_hold` or `closed`, and from `on_hold` to `active` or `closed`. Closed cases cannot reopen. Closing a case requires at least one evidence record, acceptance of every case evidence item, and resolution or closure of every remediation unless it is covered by a future-dated active risk acceptance. Closure failures return HTTP 409 without changing state.

## Evidence provenance and audit

Evidence stores the supplied content SHA-256 after hexadecimal validation and persists an immutable `manifest_sha256` derived from tenant, case, run, evidence identity, source, title, content digest, and technique linkage. Review status and analyst notes are mutable fields and are excluded from the manifest digest, so review updates do not change provenance.

The existing chained JSONL audit log remains the authoritative integrity check for API operations. The case governance history is an append-only local record of case, evidence, remediation, assessment-link, and risk-acceptance decisions. Governance summaries and metadata are redacted for common inline credential and token assignments before persistence.

## Export contract

`GET /api/v1/cases/{case_id}/export` is a read-only, tenant-safe report contract. It returns the server-derived tenant, campaign-compatible case data, evidence, remediations, governance history, risk and coverage trends, detection-tuning recommendations, generation time, and a deterministic manifest digest. It contains metadata and provenance hashes, not raw telemetry, credentials, uploaded files, or external-system mutation controls.

## Cross-role integration

Platform orchestration should link completed assessment runs through the existing campaign-run endpoint and then consume the case history for explainability. Identity and API security should retain the current authentication and permission dependencies and extend tenant/resource authorization as the shared provider evolves. Reporting and frontend clients should consume the export contract rather than reconstructing KPIs or tenant filters client-side. DevOps should apply the additive case-governance migration through the formal migration runner before production startup.
