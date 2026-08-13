# AI-08 case, evidence, and remediation governance

RedPath treats an assessment campaign as a governed **case**. The case groups authorized assessment runs, normalized evidence, remediation actions, review decisions, and audit references without storing raw credentials or uncontrolled payloads. Governance operations are metadata workflows: they do not modify Wazuh, Active Directory, endpoints, network devices, or external ticketing systems.

## Security boundary

All case, evidence, remediation, risk-acceptance, KPI, export, and audit-integrity endpoints require a bearer token configured through the server environment. The setting uses comma-separated `token:role` pairs in `REDPATH_API_KEYS`; supported roles are `soc_analyst`, `remediation_owner`, `soc_lead`, and `platform_admin`. Tokens are never returned by the API or written to the audit stream. The caller may provide `X-RedPath-Actor` for audit attribution; the value is bounded and is not treated as an authentication credential.

| Capability | Minimum role | Data behavior |
| --- | --- | --- |
| Read cases, evidence, remediations, timelines, manifests, KPIs, SLA views, and exports | `soc_analyst` or `remediation_owner` | Read-only metadata and digests |
| Create cases, link assessment runs, register evidence, create remediations, and update routine remediation state | `soc_analyst` or `remediation_owner` | Audited metadata mutation |
| Review evidence and create or list risk acceptances | `soc_lead` | Audited governance decision |
| Verify audit-chain integrity | `soc_lead` | Read-only integrity result |
| Administrative access | `platform_admin` | Includes all capabilities above |

If no credential mapping is configured, protected operations fail closed with `503 governance authentication is not configured`. Missing or invalid bearer credentials return `401`; an authenticated principal with insufficient role returns `403`.

## Case lifecycle

A case starts in `active`. Every state change is checked against the transition table and creates an append-only `campaign_transitions` record containing the prior state, requested state, actor, note, and timestamp. A closed case may only be archived, and an archived case cannot be reopened through the API.

| Current state | Allowed next states |
| --- | --- |
| `active` | `in_review`, `contained`, `closed`, `archived` |
| `in_review` | `active`, `contained`, `closed`, `archived` |
| `contained` | `in_review`, `closed`, `archived` |
| `closed` | `archived` |
| `archived` | None |

Use `PATCH /api/v1/campaigns/{campaign_id}/lifecycle` with a body containing `status`, `actor`, and an optional bounded `note`. The legacy `/campaigns` resource name remains stable for existing clients; the governance contract treats the resource as the case record.

## Evidence governance

Evidence registration stores provenance metadata only: source label, evidence type, title, technique reference, notes, and a SHA-256 digest. The API validates that the digest is exactly 64 hexadecimal characters. RedPath does not accept raw credentials or require raw packet, alert, or file payloads for this workflow.

Evidence review status changes are recorded in `evidence_review_events`. The review state machine is deliberately explicit.

| Current state | Allowed next states |
| --- | --- |
| `unreviewed` | `in_review`, `accepted`, `rejected` |
| `in_review` | `unreviewed`, `accepted`, `rejected` |
| `rejected` | `in_review` |
| `accepted` | `in_review` |

A review requires a reviewer identity and may add bounded notes. Review records preserve the original evidence digest; changing the review state does not alter evidence provenance. Evidence used to verify remediation must be in `accepted` state and, when both records include a technique ID, must match the remediation technique.

## Remediation governance

Remediation records include an owner, priority, recommendation, due date, status, and optional verification-evidence reference. Due dates must be ISO calendar dates. Lifecycle notes are stored as separate `remediation_transitions` records rather than appended to the recommendation, preserving the original remediation instruction.

| Current state | Allowed next states |
| --- | --- |
| `open` | `in_progress`, `blocked` |
| `in_progress` | `open`, `blocked`, `resolved` |
| `blocked` | `open`, `in_progress`, `resolved` |
| `resolved` | `in_progress`, `closed` |
| `closed` | None |

Transitions to `resolved` or `closed` require `verification_evidence_id` referencing accepted evidence. A missing, unknown, rejected, or technique-mismatched verification record is rejected with `409`. This prevents a remediation from being closed solely by assertion. Closure is not an automated rescan, and no external system is changed.

## Risk acceptance and reporting

Risk acceptance is a time-bounded governance decision. It requires a case, remediation, or technique linkage, a finding title, a rationale of at least 20 characters, an approver, and a current-or-future expiration date. An active duplicate acceptance for the same technique or remediation is rejected. Expired acceptances remain visible and never convert an open gap into a detected control.

Coverage and executive KPI views distinguish detected techniques, open gaps, accepted risks, evidence-review backlog, overdue remediation, open critical remediation, and expiring acceptances. Accepted risk is therefore visible as a separate governance state rather than being counted as detection coverage.

## Persistence and migration

The SQLAlchemy metadata creates the new transition tables on fresh databases. The additive migration layer also checks existing `remediation_items` tables and adds the nullable `verification_evidence_id` column when it is absent. The migration does not drop tables, rewrite evidence, or delete records. Existing deployments should still take a normal database backup before upgrading and should run the repository test suite after applying the release.

## Contract examples

Authenticated case creation:

```http
POST /api/v1/campaigns
Authorization: Bearer <configured-token>
X-RedPath-Actor: analyst@example
Content-Type: application/json

{
  "name": "Identity exposure review",
  "objective": "Review authorized lab findings and govern evidence-backed remediation.",
  "owner": "soc-engineering",
  "scope_snapshot": ["192.168.56.0/24"]
}
```

Evidence-backed remediation closure:

```json
{
  "status": "closed",
  "actor": "soc-lead",
  "verification_evidence_id": "<accepted-evidence-id>",
  "note": "Closure verified against the accepted regression fixture."
}
```

The API records an audit event for each case creation, run link, evidence registration or review, remediation creation or lifecycle change, and risk-acceptance decision. Audit integrity can be checked by a lead at `GET /api/v1/integrity/audit`.
