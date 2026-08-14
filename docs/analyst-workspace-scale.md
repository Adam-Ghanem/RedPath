# Scalable Analyst Workspace

## Purpose

The authenticated analyst workspace supports high-volume defensive review without widening tenant scope or introducing operational mutations. It provides windowed record lists, keyboard navigation, bounded URL-safe query state, saved-filter contracts, breadcrumbs, telemetry freshness degradation, and privacy-safe export preview states.

The workspace remains read-only. It does not create discovery jobs, capture packets, alter cases, change evidence review state, deploy detection rules, mutate SIEM data, or perform downloads. Server-side authorization remains the control point for every API request.

## Read-only data contract

| Surface | Read-only source | Bounded behavior |
| --- | --- | --- |
| Asset catalog | `GET /api/v1/inventory/assets?limit=...` | The client clamps the asset limit to 1–100, then window-renders the selected page. |
| Detection catalog | `GET /api/v1/detections/rules` | The client window-renders results and retains only the first 1,000 matching rows for an interactive query. Server pagination is the next backend contract requirement for larger catalogs. |
| Evidence ledger | Authenticated summary evidence data | Search and review-state filtering remain in memory and never expand backend scope. |
| Case register | `GET /api/v1/cases` | Window-rendered result pages and a tenant-scoped read-only case export preview. |
| Case export preview | `GET /api/v1/cases/{id}/export` | Shows only section counts. It never displays tenant IDs, actor IDs, canonical evidence payloads, or triggers a download. |

The primary virtualized list renders only the viewport plus four overscan rows on either side. With the 360 px viewport and 68 px row height, this is normally at most 14 rendered options regardless of the active result page. Workspace pages are capped at 250 records and client-side matching is capped at 1,000 records. These caps prevent large DOM growth and accidental unbounded rendering; they do not replace future server pagination for catalogs larger than the documented read contracts.

## URL-safe query and saved filters

The query state is represented in the analyst route hash using only `view`, `q`, `review`, `page`, `selected`, and `saved` values. Text is stripped of control characters and limited to 96 characters. Page numbers are clamped to 1–10,000. Selected identifiers are limited to safe route characters and 128 characters. Query updates use `history.replaceState`, avoiding history spam during typing.

| Saved filter | Scope | Contract |
| --- | --- | --- |
| All records | Workspace | Clears the active workspace query. |
| Evidence review backlog | Evidence | Opens evidence with the `unreviewed` review state. |
| Active cases | Cases | Opens the case register filtered by `active`. |
| Detection catalog | Workspace | Opens the read-only detection catalog. |

Saved filters are client-side presentation contracts. They do not convey tenant IDs, permissions, actor identity, or backend query authority. The backend still derives tenant scope and validates every request through authentication and RBAC.

## Accessibility and navigation

The workspace uses semantic tablists, tabs, and a tabpanel. Arrow Left, Arrow Right, Home, and End move between data views. The virtualized list uses `listbox` and `option` semantics with `aria-activedescendant`, `aria-posinset`, and `aria-setsize`; Arrow Up, Arrow Down, Home, and End select records without requiring a pointer. Search, saved-filter, evidence-review filter, pagination, telemetry status, and breadcrumbs have explicit accessible names or status semantics.

Breadcrumbs show the current workspace, view, and selected redacted record label. Focus-visible styling is maintained throughout the dark interface. The list offers a usable narrow-screen layout, and motion-sensitive users do not receive essential animation.

## Telemetry freshness and safe failure

A snapshot older than 15 minutes is marked stale. An unavailable or invalid snapshot timestamp is marked unavailable. The existing tenant-scoped data remains visible as a read-only cache, but the case export preview is paused for stale or unavailable telemetry. The UI does not retry aggressively, broaden a query, infer missing data, or switch to a global endpoint.

Loading, empty, authorization, rate-limit, network, and not-found states use bounded messages. A retry is always a read-only request. A selection that disappears from a new tenant-scoped response is treated as unavailable rather than retained or dereferenced.

## Privacy and security controls

Network references are masked in high-throughput lists and detail panels. The UI does not render tenant identifiers, actor identities, provenance hashes, full evidence hashes, canonical manifests, raw PCAP values, raw packet data, raw DNS values, rule condition values, or token-like text. Display text is redacted for email-like values, IPv4 values, and token-like phrases before it is placed in the high-throughput UI.

Role labels are server-derived and presentation-only. Viewer sessions are explicitly marked read-only. Authentication, tenancy, RBAC, resource authorization, audit attribution, rate limiting, redaction, and export permissions remain mandatory server-side responsibilities.

## Migration and rollback

This frontend-only change introduces no tables, columns, indexes, Alembic revisions, or persisted saved-filter records. **Migration:** none required. **Downgrade:** none required. **Rollback:** revert the frontend commit or deploy the previous frontend bundle. Backend schemas and stored data remain unchanged.
