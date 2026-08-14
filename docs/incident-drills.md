# Incident runbook drills

These drills validate that release operators can respond safely without performing live scanning, packet capture, remote-state mutation, or unsafe deployment automation. A drill uses synthetic fixtures, aggregate metrics, or an isolated environment. Every production action remains manual and approval-gated.

## Drill matrix

| Scenario | Trigger | Expected safe response | Prohibited response | Evidence |
| --- | --- | --- | --- | --- |
| Readiness failure | Readiness probe fails after a candidate change | Pause promotion, remove the unhealthy instance from traffic, compare with the last verified artifact | Bypass readiness or authentication | Correlation-safe diagnostics and operator decision |
| Tenant/RBAC boundary | Synthetic cross-tenant authorization check fails | Fail closed and preserve server-derived actor and tenant predicates | Display records across tenants | Test result and access-review record |
| Audit integrity | Audit-chain verification fails | Preserve source evidence read-only and restrict evidence-affecting actions | Rewrite or delete audit history | First invalid event reference without raw payload |
| Backup restore | Backup digest or isolated readiness check fails | Discard the isolated candidate and keep the source unchanged | Overwrite the production source | Manifest, digest, timeline, and approval |
| SLO/error budget | Error budget is exhausted | Pause promotion and open an operator-owned incident | Disable telemetry, rate limits, or tenant controls | Aggregate SLO report and decision |

## Execution contract

Before a drill, record the approved change, operator, reviewer, scenario, source release, synthetic or isolated target, start time, and stop conditions. Use `PYTHONPATH=backend python ci/incident_drill.py --all --json` to validate that the runbook matrix is complete. The command performs no network request and does not call a deployment or recovery API.

For a recovery scenario, use [`docs/backup-restore-drill.md`](backup-restore-drill.md) and `PYTHONPATH=backend python ci/verify_backup.py --self-test` for the local synthetic check. For an SLO scenario, use [`docs/slo-reporting.md`](slo-reporting.md) with aggregate counters only.

A drill fails closed when a required invariant is unavailable, ambiguous, or outside its performance bound. Do not broaden access, disable RBAC, skip audit verification, weaken TLS, or run arbitrary commands to make a drill pass. Preserve the minimum evidence needed for review and redact secrets, raw telemetry, packet data, customer data, actor identity, and tenant identifiers.

## Success criteria

The runbook is ready when each scenario has an owner, approval gate, trigger, stop condition, safe response, prohibited response, evidence record, and rollback decision. Drill completion does not authorize production deployment; it is evidence for a separate release decision.
