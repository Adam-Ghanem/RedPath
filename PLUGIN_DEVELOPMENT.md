# RedPath Plugin Development

RedPath plugins are **read-only, declarative adapters**. A plugin may normalize authorized observations and propose a plan, but it must never execute external commands, scan targets, collect credentials, alter security controls, or bypass the scope guard.

## Contract

Implement `RedPathPlugin` from `backend/app/plugins/base.py`. Every plugin exposes an immutable `PluginManifest`, a `plan(context)` method, and an `analyze(context, observations)` method. Use a lowercase `plugin_id` matching `^[a-z0-9][a-z0-9_.-]{2,63}$`; declare non-empty capabilities; preserve the caller tenant; and keep `read_only=True`.

## Safety Rules

Plugins receive a validated `IntegrationContext`. Respect its tenant, authorized targets, requested scopes, and effective dry-run value. Treat observations as untrusted input and validate them with the normalized models before analysis. Do not log raw payloads, secrets, identities, tokens, cookies, or telemetry bodies. Return typed findings and warnings rather than side effects.

## Registration and Tests

Register only through `PluginRegistry`, which rejects duplicate IDs, invalid manifests, and non-read-only adapters. Add focused tests for manifest validation, tenant isolation, dry-run behavior, scope denial, invalid observations, and the plan/analyze response contracts. Run `pytest`, `ruff check`, and dependency checks before opening a pull request.

## Database Changes

Schema changes must be migration-managed. Create and review an Alembic revision from the repository root with `alembic revision --autogenerate -m "describe change"`; inspect both upgrade and downgrade paths; then apply it only in the target environment. Do not introduce `create_all()` calls in new feature code.
