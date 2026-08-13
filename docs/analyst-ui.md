# Analyst UI

## Scope

The authenticated analyst workspace provides four read-only drill-down views over server-authorized RedPath data: inventory assets, detection rules, evidence, and cases. It is entered through the main frontend navigation and keeps the existing summary console as the first view. The detail module is lazy-loaded so the initial analyst route does not pay the full cost of the data tables and evidence panels.

The workspace does not present raw secrets, canonical evidence payloads, tenant identifiers, actor identifiers, raw PCAP analysis values, or secret-bearing detection condition values. It renders bounded operational metadata and explicitly communicates when a record is redacted, unavailable, not found, or pending review.

## Stable read-only client boundary

| View | Read-only endpoints | UI behavior |
| --- | --- | --- |
| Assets | `GET /api/v1/inventory/assets?limit=...` | Bounded client pagination, search across server-provided asset labels, network identity, hostname, and services, plus a selected asset summary. |
| Detections | `GET /api/v1/detections/rules` | Searchable rule catalog with technique, source, deployment, approval, and bounded-condition summary. Condition values are not rendered. |
| Evidence | `GET /api/v1/evidence`, `GET /api/v1/evidence/{id}/manifest`, `GET /api/v1/evidence/{id}/pcap` | Review-state filtering, hash previews, manifest digest metadata, and redacted PCAP packet/flow/DNS counts. Raw canonical payloads and raw packet values are withheld. |
| Cases | `GET /api/v1/cases`, `GET /api/v1/cases/{id}/export` | Tenant-scoped case search, pagination, governance history, evidence count, remediation count, and status summary. Case mutations remain server-authorized workflows. |

The client clamps inventory limits to the range 1–100 and URL-encodes all detail resource identifiers. Requests carry same-origin credentials, use the in-memory bearer session, accept an abort signal where the view can be unmounted or retried, and normalize errors without exposing raw backend response bodies.

## Role-aware behavior

The authenticated session banner is derived from `/api/v1/auth/me`. A viewer is explicitly labeled `Viewer · read-only`; other authenticated roles are shown as server-derived role labels with a read-only indicator. Role presentation does not authorize requests. The backend remains the source of truth for tenant isolation, resource authorization, RBAC, rate limits, audit integrity, and actor attribution.

The frontend does not expose create, update, review, remediation lifecycle, discovery, packet injection, SIEM mutation, or detection deployment controls. The detail views only call the documented GET contracts. Authorization failures render bounded error states rather than retrying with broadened scope or attempting alternative resources.

## Accessibility and interaction design

Detail views use semantic tablists and tabpanels. The selected tab is the only tab in the normal tab order, and Arrow Left, Arrow Right, Home, and End move focus between views. Search fields and review-state filters have explicit labels. Data rows use real table headers, selected rows expose `aria-pressed`, pagination has named controls and disabled boundaries, and loading, empty, and error states use status or alert semantics. Focus-visible outlines remain visible against the dark theme, and reduced-motion preferences disable loading animation.

## Loading, error, and empty states

Each catalog has a loading state, an empty state with tenant-scoped copy, and a bounded error state with a read-only retry. The case view can retry both the list and the selected detail export. A missing optional PCAP detail does not erase the parent evidence record; it remains visible with the redaction summary and a safe inline status. Rate-limit errors instruct the analyst to wait rather than increasing request frequency.

## Performance

The drill-down module is loaded with `React.lazy` and `Suspense` after the authenticated summary is ready. Detail lists use bounded server fetches where available and client-side pagination over the received tenant-scoped collection. Search and filter operations only transform the in-memory response and do not trigger uncontrolled network requests.

## Tenancy, privacy, and safe failure

Every operational request is authenticated and must be authorized against the current tenant by the backend. The UI never accepts an editable tenant ID, actor, reviewer, or approver field for an operational action. Cross-tenant empty and not-found behavior is displayed as a generic no-records or unavailable state. Evidence hashes are truncated for display, canonical manifest content is never rendered, and PCAP detail is limited to redaction-safe summary counts.

When an endpoint is unavailable, the UI fails closed: it displays a generic message, does not fall back to global data, does not broaden the query, and does not perform a write or remote action. Retry is always a bounded read-only request.

## Migration and rollback

This change adds no database tables, columns, indexes, migrations, or persistence behavior. **Migration:** none required. **Rollback:** revert the single frontend commit or deploy the previous frontend bundle; backend schemas and persisted data remain unchanged. If future case or evidence actions are added, they must first receive server-side contracts, migration review, tenancy tests, audit coverage, and an explicit rollback plan before UI exposure.
