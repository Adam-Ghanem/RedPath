# Authenticated Analyst Workspace Integration

## Product boundary

The RedPath analyst workspace is a read-only operational view over authenticated, tenant-scoped backend summaries. The main frontend exposes the workspace through the primary navigation and a stable `#analyst-console` route state. Returning to the RedPath home view is available from the workspace brand, header, error state, and sign-in state, so the console does not create a navigation dead end.

The browser never becomes the source of truth for actor identity, tenant membership, roles, review attribution, or audit records. After authentication, the backend supplies the authenticated principal through `/api/v1/auth/me`; the workspace renders that response directly in the session banner. It does not display a fabricated user, reviewer, tenant, or approval record.

## Authenticated read-only contract

| Endpoint | Method | Frontend use | Security expectation |
| --- | --- | --- | --- |
| `/api/v1/auth/token` | POST | Establishes an in-memory bearer session from user-provided credentials. | Rate-limited, server-authenticated, no browser persistence of the token. |
| `/api/v1/auth/me` | GET | Resolves server-derived username, tenant, roles, and session version. | Requires a valid bearer token; never accepts actor identity from the UI. |
| `/api/v1/scope` | GET | Shows allowed CIDRs and dry-run default. | Requires authentication and remains server-authoritative. |
| `/api/v1/kpis/executive` | GET | Provides posture KPIs. | Tenant-scoped and role-authorized server-side. |
| `/api/v1/scorecards/coverage` | GET | Provides detection coverage. | Tenant-scoped and read-only. |
| `/api/v1/runs?limit=8` | GET | Shows recent validation runs. | Read-only and tenant-scoped. |
| `/api/v1/evidence` | GET | Shows evidence records pending or complete review. | References only; raw sensitive payloads stay server-side. |
| `/api/v1/remediations/sla` | GET | Shows remediation posture. | Read-only; ownership and lifecycle mutation remain server-side workflows. |
| `/api/v1/detection-tuning` | GET | Shows rule-tuning recommendations. | Recommendations only; the frontend does not mutate SIEM or detection rules. |
| `/api/v1/integrity/audit` | GET | Shows audit-chain verification. | Read-only integrity result; audit writes remain backend-controlled. |

The client exposes GET methods for the operational workspace. The authentication POST only establishes an in-memory bearer session; it does not create cases, review evidence, change remediation state, run discovery, modify Wazuh/SIEM data, or execute remote actions.

## State behavior

The workspace uses explicit loading, authentication-required, ready, error, and empty queue states. API failures are normalized to safe messages and never render raw response bodies. A `401` returns the sign-in state, a `403` reports that the authenticated role is not authorized, and a `429` explains that the backend rate limit remains in force before offering a retry. All retry controls repeat read-only requests.

| State | User-visible behavior | Accessibility behavior |
| --- | --- | --- |
| Loading | Authenticated workspace summary is being retrieved. | `role="status"` and polite live-region text. |
| Authentication required | Credential form requests tenant slug, username, and password. | Labels, autocomplete hints, alert copy, and keyboard-reachable submit/return controls. |
| Ready | Server-derived actor, tenant, role, scope, KPIs, queues, runs, and audit posture render. | Session identity has an accessible label; navigation exposes `aria-current`. |
| Error | Safe message, status-aware guidance, read-only retry, and return-to-home control. | `role="alert"` and visible focus states. |
| Empty queue | Explicit no-records copy; no action encourages broader collection. | Polite status message. |

The analyst queue uses a roving tab pattern. Only the selected tab is in the normal tab order, and Arrow Left, Arrow Right, Home, and End move focus between queue tabs while updating `aria-selected` and the panel relationship. The queue panel itself is keyboard-focusable for a clear focus target.

## Tenant and RBAC boundaries

The frontend may use the server-derived roles for presentation decisions, but those decisions are not authorization. The backend must enforce role permissions, tenant isolation, resource authorization, rate limits, audit integrity, and dry-run policy for every request. In particular, a viewer may read authorized summaries but must not be offered a browser shortcut to recon, mutations, evidence review, remediation lifecycle changes, identity management, or remote SIEM operations.

Actor names, reviewer names, approvers, tenant IDs, and resource ownership must be taken from authenticated backend responses. The UI must not accept actor or tenant identifiers as editable fields for operational actions. Future case and evidence mutations should be server-side audited jobs with the authenticated principal attached by request context.

## Deferred contracts

Asset findings and weighted graph snapshots are not part of the authenticated summary contract used here. Until their tenant-scoped read-only endpoints are available, the main analyst workspace should not present synthetic records as live telemetry. New endpoints should follow the existing pattern: typed response models, authenticated dependencies, tenant-scoped queries, generic error responses, and backend audit or integrity semantics where appropriate.
