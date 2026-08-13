# Release operations and service assurance

This document defines the release-time operating contract for RedPath. It is intentionally validation-first: CI verifies the release artifact, while production operators decide whether to promote, pause, or roll back through the protected deployment process. No release job should discover networks, mutate SIEM or directory services, inject packets, or execute arbitrary input.

## Service-level objectives

The following targets are proposed production objectives and must be measured against the deployed environment before being adopted as contractual commitments.

| Signal | Target | Measurement | Safe response |
| --- | --- | --- | --- |
| Readiness availability | 99.5% monthly | Successful `GET /api/v1/health/ready` responses during scheduled service windows | Remove an unhealthy instance from traffic; do not bypass readiness checks |
| API latency | p95 below 1 second for authenticated read-only requests | Route-template latency histogram, excluding uploads and report generation | Investigate the slow route and preserve request budgets |
| Server error rate | Below 1% over five minutes | 5xx completion counter divided by total requests | Pause promotion and inspect the release correlation ID |
| Audit verification | 100% successful chain checks | Scheduled read-only audit-integrity verification | Freeze evidence-affecting release actions and preserve the first invalid event |
| Recovery point | 15 minutes for production-managed persistence | Timestamp of the newest verified backup | Use the last verified backup; never overwrite the source during a drill |
| Recovery time | Four hours for a documented production restore | Time from restore authorization to isolated readiness | Restore into an isolated environment and require validation before cutover |

The recovery targets are planning targets, not evidence that the demo SQLite profile meets them. The demo profile is local and should be backed up according to the operator’s selected cadence.

## Structured logs

HTTP completion and failure logs should be structured JSON with bounded fields: event name, UTC timestamp, log level, release identifier, route template, method, status class, duration in milliseconds, and a validated request correlation identifier. Logs must not contain request bodies, query values, cookies, authorization headers, credentials, raw telemetry, packet bytes, target lists, or unredacted actor and tenant data.

Use the request correlation identifier to join an API response, an audit event, and a release incident. If a future collector maps it to a distributed trace, retain the same redaction boundary. Do not accept arbitrary trace metadata as a reason to log sensitive request content.

## Metrics and traces

The current metrics surface is a bounded Prometheus-compatible endpoint. Labels are limited to method, route template, and status class; resource identifiers and query values must never become labels. Scrape metrics only from an authenticated monitoring network or a protected sidecar. For multiple workers, aggregate at the collector rather than assuming the in-process registry is global.

RedPath currently provides request correlation rather than a full distributed tracing dependency. A future tracing adapter should be opt-in, sample safely, propagate only validated correlation context, and record route timing without payload attributes. Trace export failure must not fail an API request or weaken tenant/RBAC checks.

## Release verification runbook

Before promotion, verify the exact commit, required CI checks, SBOM artifacts, dependency-review result, container scan result, migration check, documentation check, and release verification output. Confirm that the image runs as a non-root user, uses a read-only filesystem where supported, drops capabilities, enables `no-new-privileges`, exposes only the documented listeners, and passes liveness and readiness probes.

When readiness fails, stop promotion, capture the release identifier and correlation-safe diagnostics, and compare the failure with the last known-good artifact. When server errors rise, pause promotion and use bounded logs and metrics to identify the affected route. Do not retry unboundedly and do not disable authentication, tenant predicates, audit logging, dry-run defaults, or scope validation to restore availability.

When audit-chain verification fails, preserve the evidence files read-only, record the first invalid event, restrict evidence-affecting actions, and escalate for investigation. When a tenant or RBAC invariant fails, fail closed, revoke the affected operational path through the protected administrative process, and do not expose cross-tenant records while diagnosing the issue.

## Safe failure and rollback

Rollback means selecting a previously verified immutable application artifact through the protected deployment process. It does not mean deleting data, rewriting audit history, mutating external SIEM or directory state, or running an ad hoc shell command. Database changes require a reviewed forward migration and a compatible rollback or restore plan before promotion. If a migration cannot be safely reversed, pause the release and restore an isolated copy for analysis rather than changing the production source in place.

Every incident record should include the exact release identifier, check results, start and end times, safe correlation identifiers, affected service surface, decision owner, and follow-up action. Do not include secrets, raw telemetry, packet captures, credentials, or customer data in the incident record.
