# Database Migration Workflow

RedPath database changes must be additive, tenant-safe, auditable, and reversible through deployment controls. A migration must not erase data, bypass tenant predicates, mutate an external system, or make a fresh application start depend on an unavailable remote service.

## Forward migration

For a schema change, create a numbered lower-snake-case SQL artifact under `backend/migrations/` using the next available filename in the relevant migration chain. Keep the statement set additive: create tables or indexes, add nullable or safely defaulted columns, and add compatibility projections. Do not edit an already-applied migration. When an Alembic revision exists for the deployment, the release process must apply it with `alembic upgrade head` against the reviewed database URL; the revision and the SQL artifact must represent the same schema contract. The current prototype also runs the idempotent `run_migrations()` compatibility runner during database initialization, so any external migration must remain safe when that runner executes afterward.

Before applying a migration to a tenant-bearing deployment, take the approved database backup or snapshot and record the migration commit, target environment, operator identity, and resulting schema version. Apply the migration in a transaction where the database supports transactional DDL. Start with a staging or restored copy, then run the repository migration validation and application smoke tests before production rollout.

```bash
alembic upgrade head
PYTHONPATH=backend python ci/check_migrations.py
pytest -q backend/tests/test_migrations.py
```

The validator checks filename discipline, additive DDL, absence of destructive statements, required tenant columns, legacy-tenant backfill, schema-version idempotence, and the existence of this rollback procedure. The SQL artifact set is intentionally validated even when a deployment uses Alembic so that the prototype compatibility path cannot silently diverge.

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

This platform contract change does not add or alter a database table, column, index, or migration artifact. Its migration contribution is the validation and rollback backbone above, together with compatibility tests for versioned contracts and bounded cursors. Future persistence changes must add their own additive migration and update the migration tests before merge.
