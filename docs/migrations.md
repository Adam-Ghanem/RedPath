# Database Migration Workflow

RedPath database changes must be additive, tenant-safe, auditable, and reversible through deployment controls. A migration must not erase data, bypass tenant predicates, mutate an external system, or make a fresh application start depend on an unavailable remote service.

## Forward migration

For a schema change, create one Alembic revision under `backend/alembic/versions/` with the next reviewed revision identifier. Keep the statement set additive: create tables or indexes, add nullable or safely defaulted columns, and add compatibility projections. Do not edit an already-applied revision or add parallel SQL artifacts under `backend/migrations/`. The release process applies the reviewed revision with `alembic upgrade head` against the reviewed database URL, and the compatibility runner remains Alembic-backed during application initialization.

Before applying a migration to a tenant-bearing deployment, take the approved database backup or snapshot and record the migration commit, target environment, operator identity, and resulting schema version. Apply the migration in a transaction where the database supports transactional DDL. Start with a staging or restored copy, then run the repository migration validation and application smoke tests before production rollout.

```bash
alembic upgrade head
PYTHONPATH=backend python ci/check_migrations.py
pytest -q backend/tests/test_migrations.py
```

The validator checks revision discipline, additive DDL, absence of destructive statements in forward migration sources, required tenant columns, legacy-tenant backfill, schema-version idempotence, and the existence of this rollback procedure.

The evidence-governance revision `4f2a6c1e9b77` follows PCAP lifecycle revision `22d614b2aac8` and adds tenant-scoped legal holds, append-only retention decisions, and approval-only deletion requests. It stores metadata and decisions only; it does not retain packet bytes or provide a deletion executor.

The inventory reliability revision `c14f9b72d6e1` is Alembic-only and follows `22d614b2aac8`. It adds tenant-scoped lease, checkpoint, retry-budget, result-compaction, and composite-index state. Apply it with `alembic upgrade head` only after workers are quiesced or the deployment can tolerate additive fields appearing during rollout. The downgrade function removes only the state and indexes introduced by this revision after a reviewed maintenance window; production rollback should follow the application-revert, snapshot, or compensating-migration procedure below rather than an ad hoc database command.

## Rollback

Rollback is a deployment decision, not an automatic destructive SQL operation. If an additive migration causes an application regression, stop the affected rollout, keep the new columns or tables intact, and revert the application to the last compatible commit when the old application can safely ignore the additive schema. Restore the approved database snapshot only when data integrity or operational recovery requires it and the restore has been reviewed for tenant and audit consequences.

If the schema must be adjusted after partial rollout, create a new forward, additive compensating migration. Do not remove columns, truncate tables, drop tenant predicates, rewrite audit history, or run an ad-hoc destructive statement as a rollback. A restore or compensating migration must preserve tenant ownership, server-derived actor fields, audit-chain continuity, redaction boundaries, and read-only external-system guarantees.

The release coordinator must record whether rollback used application revert, snapshot restore, or a compensating migration; the affected schema version; validation results; and any tenant-visible impact. The platform does not claim a migration is rolled back merely because an application commit was reverted.

## Validation

A migration is ready for release only when the following checks pass on the exact candidate commit:

```bash
PYTHONPATH=backend python ci/check_migrations.py
pytest -q backend/tests/test_migrations.py backend/tests/test_kernel_contracts.py
```

Reliability changes that add or alter a database table, column, or index must include an Alembic revision, downgrade function, migration-contract test coverage, and a documented maintenance-window rollback. The inventory reliability revision is validated by the same migration and application gates above; no legacy SQL migration artifact is added.

The evidence-governance change adds one Alembic revision and focused upgrade/downgrade/re-upgrade coverage. Future persistence changes must add their own additive revision and update migration tests before merge.
