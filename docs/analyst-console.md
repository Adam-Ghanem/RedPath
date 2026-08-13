# Dark SOC Analyst Console

## Purpose

The **Dark SOC Analyst Console** is a focused, read-only operational workspace at `/console`. It converts the existing RedPath API’s summary resources into an analyst-facing priority view without placing raw evidence payloads, secrets, discovery controls, or mutating workflow shortcuts in the browser. The public synthetic case-file demo remains at `/`.

> The console is an analyst **decision surface**, not a collection or execution surface. It only reads authorised summary data and deliberately sends no mutation requests.

## Vertical slice

The module lives under `frontend/src/features/analyst-console/` and has three separable concerns. `contracts.ts` mirrors the typed shapes served by the existing FastAPI summary endpoints. `api.ts` provides a same-origin client whose only request method is `GET`. `model.ts` deterministically prioritises remediation, detection-tuning, evidence-review, and run-summary queues. `AnalystConsole.tsx` renders loading, unavailable, empty, and ready states, while `analyst-console.css` supplies the responsive dark visual system.

| Workspace surface | Data displayed | Analyst value | Data intentionally omitted |
| --- | --- | --- | --- |
| Exposure posture | Risk score, coverage, critical findings, technique gaps | Establishes the current decision context | Raw graph payloads and raw alerts |
| Remediation priorities | SLA state, priority, owner, due date and title | Brings overdue or due-soon defensive action forward | Update controls and free-form mutations |
| Detection engineering | Technique, gap count, rule intent and event-source labels | Identifies the next defensive validation work | Raw telemetry, query execution and rule deployment |
| Evidence assurance | Review status, evidence title/type, audit-chain result | Separates defensible evidence from backlog | Hashes, notes and canonical payloads |
| Validation runs | Scenario, summary, dry-run state, timestamp and coverage | Preserves a reviewable assessment timeline | Run initiation or scenario execution |

## Typed API contract

The console snapshots eight existing endpoints concurrently. The frontend uses `VITE_REDPATH_API_BASE_URL` when configured; otherwise it uses the same-origin `/api/v1` base. The Vite development server already forwards `/api` to the local backend. The demo Nginx configuration now forwards `/api/` to the Docker Compose `api` service, avoiding a browser cross-origin dependency.

| Endpoint | Typed frontend shape | Console use |
| --- | --- | --- |
| `GET /api/v1/scope` | `ScopeResponse` | Shows authorised CIDRs and the server dry-run default. |
| `GET /api/v1/kpis/executive` | `ExecutiveKpis` | Produces risk, critical-finding and backlog counters. |
| `GET /api/v1/scorecards/coverage` | `CoverageScorecard` | Separates observed and effective coverage. |
| `GET /api/v1/runs?limit=8` | `AssessmentRunSummary[]` | Renders the recent validation timeline. |
| `GET /api/v1/evidence` | `EvidenceResponse[]` | Counts review backlog and lists only safe metadata. |
| `GET /api/v1/remediations/sla` | `RemediationSlaItem[]` | Sorts remediation records by SLA state then severity. |
| `GET /api/v1/detection-tuning` | `DetectionTuningItem[]` | Sorts rule-tuning work by priority and gap count. |
| `GET /api/v1/integrity/audit` | `IntegrityVerification` | Displays audit-chain assurance without showing the digest. |

## Safety and access-control boundary

The client is intentionally **least-privilege by design**. Its typed adapter exposes only `getSnapshot()` and always makes same-origin `GET` requests with `credentials: "same-origin"`. Failure messages report only the HTTP status; they do not reflect response bodies into the UI. Rendering hides raw evidence notes, hashes, canonical manifests, raw Wazuh data, targets, credentials, and raw API errors.

The console does not replace service-side identity, tenant isolation, authentication, or resource authorization. The current UI assumes the reverse proxy and API deployment enforce those controls before a user can reach the route or any endpoint. A production rollout must protect the eight API endpoints with authenticated, role- and tenant-scoped server-side authorization and audit every access decision. The console includes no token persistence and does not store security data in browser storage.

## Operating the console

For local frontend development, start the backend on port `8000` and run `pnpm dev` in `frontend`; then open `http://localhost:5173/console`. The Vite proxy forwards same-origin API traffic. For the bounded demo profile, run the documented Docker Compose command and open `http://localhost:5173/console`; the Nginx `/api/` proxy forwards requests to the API container.

The route is a lightweight SPA route: `App.tsx` chooses `AnalystConsole` only when the normalised browser path is `/console`; all other paths render the existing synthetic public demo. Nginx’s existing SPA fallback supports direct navigation to `/console`.

## Verification

The focused tests cover deterministic view-model behaviour and API-client boundaries. `model.test.ts` verifies severity classification, defensive percentage clamping, remediation and tuning priority order, review-backlog accounting, recent-run ordering, and malformed timestamp handling. `api.test.ts` verifies that a snapshot loads through eight same-origin typed `GET` requests and that a failed endpoint produces a bounded `RedPathApiError` rather than returning response content to the UI.

Run the following commands from `frontend`:

```bash
pnpm test
pnpm lint
pnpm build
```

## Current limitations and next integration point

This milestone deliberately stops at a safe, read-only vertical slice. It does not add case creation, evidence review mutations, remediation updates, detection-rule deployment, collection controls, bulk exports, automatic refresh, browser-stored authentication, or client-side authorization logic. Those functions belong in later case-management and identity/RBAC modules with dedicated backend policy enforcement, auditable background jobs where needed, and tests for every permission boundary.
