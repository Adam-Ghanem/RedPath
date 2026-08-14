# Platform Reliability Contracts

RedPath reliability primitives are synchronous, bounded, and safe to compose into authenticated workflows. They do not start background daemons, create unbounded queues, contact external systems, or retry a network action implicitly. A caller decides whether a retry is appropriate and applies the returned delay within its own bounded request or job budget.

## Idempotency

`IdempotencyKey` accepts an allow-listed ASCII key between 8 and 128 characters. `IdempotencyStore` scopes claims by the server-derived tenant ID, server-derived actor, and key value, and binds the claim to a canonical request fingerprint. A matching completed claim returns a replay result; a matching in-progress claim returns `idempotency_in_progress`; and a different fingerprint returns `conflict`. The store is thread-safe for concurrent claims, expires records after a bounded TTL, and evicts the oldest record at a configured maximum size.

The store is an in-process primitive for safe internal write workflows, not a distributed lock or an authorization mechanism. A production adapter that spans multiple API workers must provide an equivalent tenant-scoped durable store behind this interface before enabling cross-worker write replay. Callers must perform authentication, RBAC, resource authorization, validation, and audit recording before claiming or completing a write. The idempotency key never replaces server-derived identity.

## Retry and failure contracts

`RetryPolicy` provides deterministic exponential backoff with bounded attempts, multiplier, and delay. Only explicitly transient failure codes—rate limiting, dependency unavailability, and timeout—are retryable. Validation, authentication, authorization, tenant mismatch, conflict, and internal failures do not receive retry hints. No primitive sleeps, schedules, or repeats an operation automatically.

`FailureEnvelope` is the stable safe-failure shape. It contains an allow-listed code, safe human-readable message, request ID, retryability, and an optional bounded retry delay. It excludes exception text, stack traces, credentials, raw requests, target details, and provider payloads. The taxonomy is deterministic so API, worker, and frontend consumers can handle failure classes without parsing messages.

## Correlation and domain events

`CorrelationContext.from_principal()` derives tenant and actor only from the authenticated server principal and combines them with a request ID and UUID correlation ID. `DomainEvent` carries tenant, actor, request, correlation, event type, and occurrence metadata with a scalar-only payload. Raw packets, raw telemetry, credentials, tokens, commands, and arbitrary nested objects are rejected. Event emission is a synchronous handoff contract; this change does not add an event broker or background consumer.

## Health and readiness

The public `/health`, `/health/live`, and `/health/ready` routes retain their existing response values while returning typed `HealthContract`, `LivenessContract`, and `ReadinessContract` models. Readiness is not inferred from a remote probe in this layer. Components must report bounded `HealthCheck` values, and a `ready` response is valid only when every reported check is `ok`. Tenant-scoped external connector health remains behind authenticated, permission-protected service-specific endpoints.

## Security and performance bounds

All stateful write integrations must preserve authenticated tenant and actor derivation, route-level RBAC, resource authorization, and append-only audit metadata. Idempotency records are bounded to at most 10,000 entries by default and expire within 24 hours; default claims expire after five minutes. Keys, request fingerprints, event payloads, error messages, and health details are size-limited. Retry attempts are capped at five and delay at 300 seconds. Domain-event payloads contain at most 32 scalar fields, health checks at most 32 components, and no reliability primitive creates an unbounded queue.

This change adds no database tables, columns, indexes, or Alembic revisions. Therefore no migration or downgrade is required. If a future implementation persists idempotency records or event state, it must add an additive Alembic revision, preserve tenant predicates and actor provenance, and document application-revert, snapshot-restore, or forward-compensating rollback before merge.
