# Case Governance Integration

Case governance is a tenant-scoped compatibility layer over the existing campaign, evidence, remediation, and risk-acceptance resources. The API keeps the established campaign contracts while exposing `/api/v1/cases` aliases for analysts and reporting clients.

## Identity and tenancy

Every protected case operation requires the existing bearer-session authentication and `manage_cases`, `read`, or `view_audit` permission as appropriate. The service derives `tenant_id` and actor fields from the authenticated principal. Request payloads cannot select a tenant or impersonate a reviewer, remediation lifecycle actor, case-status actor, or risk-acceptance approver.

All case, evidence, remediation, risk-acceptance, governance-history, and export queries include the server-derived tenant predicate. An identifier belonging to another tenant is treated as not found. The existing RBAC dependency chain remains authoritative; this integration does not introduce a parallel authorization system.

## Transition invariants

Evidence follows the existing state machine: `unreviewed` may move to `in_review`, `accepted`, or `rejected`; `in_review` may move to `unreviewed`, `accepted`, or `rejected`; `rejected` may return to `in_review`; and `accepted` may return to `in_review` for a documented re-review. Invalid transitions return HTTP 409 and do not create a history event.

Remediation follows the existing state machine: `open` may move to `in_progress` or `blocked`; `in_progress` may move to `open`, `blocked`, or `resolved`; `blocked` may move to `open`, `in_progress`, or `resolved`; `resolved` may move to `in_progress` or `closed`; and `closed` is terminal. Assignment accepts only an active user in the same tenant. Lifecycle transitions reset verification to `unverified` for active work and `pending` when a remediation reaches `resolved` or `closed`. Only resolved or closed remediations may be verified; a rejected verification returns a non-closed remediation to `in_progress`, while closed cases reject unsafe rework. Each accepted transition creates a tenant-scoped governance event with a server-derived actor.

Cases may move from `active` to `on_hold` or `closed`, and from `on_hold` to `active` or `closed`. Closed cases cannot reopen. Closing a case requires at least one evidence record, acceptance and verified custody for every case evidence item, and every remediation to be resolved/closed and independently verified unless it is covered by a future-dated approved risk acceptance. Closure failures return HTTP 409 without changing state.

## Evidence provenance and audit

Evidence stores the supplied content SHA-256 after hexadecimal validation and persists an immutable `manifest_sha256` derived from tenant, case, run, evidence identity, source, title, content digest, and technique linkage. Review status and analyst notes are mutable fields and are excluded from the manifest digest, so review updates do not change provenance.

The existing chained JSONL audit log remains the authoritative integrity check for API operations. The case governance history is an append-only local record of case, evidence, remediation, assignment, custody, verification, assessment-link, and risk-acceptance decisions. Chain-of-custody verification requires the exact persisted immutable evidence manifest digest and records the decision, server-derived actor, and redacted note in a separate append-only custody history. Governance summaries and metadata are redacted for common inline credential and token assignments before persistence.

Evidence lifecycle governance adds the following tenant-safe interfaces:

| Interface | Boundary |
| --- | --- |
| `POST /api/v1/evidence/{evidence_id}/integrity/reverify` | Requires `view_audit`; recomputes the immutable manifest and validates metadata-only storage without reading or exporting payload bytes. |
| `POST` and `GET /api/v1/evidence/{evidence_id}/legal-hold` | Requires `manage_cases` to change a hold and `read` to view it; hold reasons and actors are server-attributed and redacted. |
| `POST /api/v1/evidence/{evidence_id}/retention-decision` and `GET .../retention-history` | Records append-only `retain`, `defer`, or `eligible_for_deletion` decisions with tenant and actor fields. |
| `POST /api/v1/evidence/{evidence_id}/deletion-request` | Creates an approval request only after an eligible retention decision and with no active legal hold; it never deletes evidence. |
| `POST /api/v1/evidence/{evidence_id}/deletion-request/{request_id}/decision` | Requires `view_audit`; approval requires a different actor from the requester and rechecks hold and retention boundaries. |
| `GET /api/v1/evidence/{evidence_id}/privacy-summary` | Returns bounded governance and storage metadata only; raw packets, payloads, credentials, and storage locators are excluded. |

The PCAP storage provider is a metadata-only abstraction. Its verification fails closed if a lifecycle record advertises a non-metadata backend, a locator, retained bytes, a non-zero byte count, or a source hash mismatch.

Risk acceptances are created with server-derived approval attribution, can be revoked or re-approved with a future expiry, and can be explicitly expired only after the persisted expiry date. Approval delegation is optional and constrained to an active same-tenant case-management user, a maximum seven-day window, no self-delegation, optional case scope, and the server-derived delegate actor. Expiry reminders are bounded to a 90-day query window, are read-only mock records with `sent=false`, and require downstream opt-in before any notification adapter is used. The expiry and approval states are included in governance history and tenant-safe exports. The SLA clock is UTC-normalized and versioned (`2.0`), uses fixed priority targets, and returns elapsed, remaining, paused, and state fields. Escalation recommendations and drafts are deterministic, bounded, mockable, opt-in, and do not send notifications or mutate remote systems.

## Decision timeline and verification evidence

Each case decision is recorded in a separate append-only hash chain with a genesis digest, server-derived tenant and actor, resource/state transition, redacted reason, and metadata digest. `GET /api/v1/cases/{case_id}/decision-timeline` recomputes each event and fails closed through `integrity_valid=false` if a persisted event is altered. The existing chained JSONL audit logger remains separate and authoritative for request-level audit integrity.

A resolved or closed remediation may record independent verification evidence only when the evidence belongs to the same tenant and case, has accepted review, has verified custody, and presents the exact immutable evidence manifest digest. Verification evidence stores metadata and the manifest hash only; it never stores raw uploaded content.

## Export contract

`GET /api/v1/cases/{case_id}/export` is a read-only, tenant-safe `case-export.v3` report contract. It returns the server-derived tenant and actor, campaign-compatible case data, evidence, remediation assignments and verification states, independent verification evidence, custody history, governance history, immutable decision timeline and integrity status, risk-acceptance decisions, SLA escalation recommendations, risk and coverage trends, detection-tuning recommendations, generation time, and a deterministic manifest digest. `GET /api/v1/cases/{case_id}/export-fixture` returns a smaller deterministic fixture containing only redacted record counts and hashes for report regression tests. These contracts contain redacted metadata and provenance hashes, not raw telemetry, credentials, uploaded files, or external-system mutation controls.

## Cross-role integration

Platform orchestration should link completed assessment runs through the existing campaign-run endpoint and then consume the case history for explainability. Identity and API security should retain the current authentication and permission dependencies and extend tenant/resource authorization as the shared provider evolves. Reporting and frontend clients should consume the export contract rather than reconstructing KPIs or tenant filters client-side. DevOps should apply the additive governance and compliance Alembic revisions through the formal migration runner before production startup. The revisions create metadata-only verification, delegation, and decision-history records and add nullable governance fields. `python3 ci/check_migrations.py` validates upgrade, repeat upgrade, downgrade, and re-upgrade. Rollback is application-first and non-destructive: deploy the prior application while retaining phase-4 metadata, then remove only the affected tables or columns in a separately reviewed, backup-verified Alembic downgrade after dependency review.

SLA queries are bounded to 512 current-tenant remediations, approval delegation reads to 256 records, verification-evidence reads to 512 records per remediation, and decision timelines to 1,000 events per case. Expiry reminder windows are capped at 90 days and reminder reads are bounded to 256 records. All results use deterministic ordering and return metadata only. Draft generation is O(R) over the bounded remediation set and performs no notification I/O. Timeline verification is O(E) over the bounded event set, and export fixture generation is O(E + R + V + H) over bounded decision, remediation, verification, and history records.
