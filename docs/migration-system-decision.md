# RedPath Migration System Decision

## Decision

RedPath will use **Alembic as its sole authoritative database migration system**. The existing startup-time `schema_migrations` runner and the unversioned manual SQL migration directory will be retired after their state changes are represented by ordered Alembic revisions.

This is the selected approach because RedPath now has persistent tenant, telemetry, evidence, governance, and risk data that require an auditable revision graph, reproducible upgrades, and verified downgrade/recovery behavior. A startup-time collection of raw `ALTER TABLE` and `UPDATE` statements cannot provide those operational guarantees or a reliable dependency order.

## Required Invariants

Alembic revisions must be the only schema-changing mechanism. Application startup may create a SQLAlchemy engine and session factory, but it must not call `Base.metadata.create_all()` or execute ad-hoc DDL/data migrations. Deployments and development environments must run `alembic upgrade head` explicitly before application startup.

The Alembic configuration must obtain the database URL from `DATABASE_URL`/RedPath settings rather than a hard-coded connection string. The revision chain must include the existing tenant backfill, telemetry correlation field, and evidence manifest changes in dependency order, with idempotent data handling where required.

## Verification Contract

The migration implementation is accepted only if a clean database can complete `alembic upgrade head`, then `alembic downgrade -1`, then `alembic upgrade head` again. The backend and frontend test suites, Ruff, Bandit, dependency audit, and frontend production build must also pass. The exact command output will be retained with the release evidence.
