# Observability contract

This release adds a dependency-light observability layer to the API. Each request receives a correlation identifier from `X-Request-ID` when it matches the safe allow-list pattern; otherwise the API generates a UUID. The identifier is returned in the response header and included in structured HTTP completion or failure logs.

> Request observability records request metadata only. It never logs request bodies, query-string values, cookies, authorization headers, or raw telemetry payloads.

The in-process registry exports Prometheus-compatible text at `GET /api/v1/metrics`. Metrics use only the bounded labels `method`, route template, and status class. Query values and resource identifiers are therefore excluded from labels. The registry exposes total requests, cumulative request duration, duration sample count, and current in-flight requests. It is designed for a single API worker; multi-worker or multi-replica deployments should scrape each worker or replace the registry with a shared collector.

| Endpoint | Purpose | Exposure guidance |
| --- | --- | --- |
| `/api/v1/health/live` | Process liveness | Safe for an orchestrator probe |
| `/api/v1/health/ready` | Application readiness | Put behind deployment ingress policy |
| `/api/v1/health` | Service, release, environment, and dry-run status | Operational/read-only |
| `/api/v1/metrics` | Prometheus-compatible metrics | Restrict to an authenticated monitoring network in production |

The health endpoints deliberately report no database credentials, Wazuh URLs, tenant data, asset values, or audit contents. `METRICS_ENABLED=false` removes the metrics endpoint for deployments that provide metrics through another sidecar or gateway.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | Structured HTTP log threshold |
| `METRICS_ENABLED` | `true` | Enables the metrics endpoint |
| `RELEASE` | `dev` | Release identifier returned by health |

The metrics registry is process-local and resets on restart. This is acceptable for local/demo use and keeps the milestone free of a new telemetry dependency; production operations should aggregate with a collector and retain deployment-level counters separately.

## Release operations

Service targets, structured log field boundaries, request-correlation guidance, proposed SLOs, safe-failure behavior, and operational runbooks are maintained in [`docs/release-operations.md`](release-operations.md). Backup and restore validation is defined in [`docs/backup-restore-drill.md`](backup-restore-drill.md). These documents describe operational procedures only; they do not authorize external-system mutation or bypass tenant, RBAC, audit, or dry-run controls.
