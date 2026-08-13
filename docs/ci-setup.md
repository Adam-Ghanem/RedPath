# CI and release-quality setup

RedPath’s canonical quality pipeline is `ci/redpath-ci.yml`. It is intentionally stored outside `.github/workflows/` because repository workflow activation requires the dedicated GitHub workflow permission. A repository maintainer can activate it with the following one-time command from a clone that has that permission:

```bash
mkdir -p .github/workflows
cp ci/redpath-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "Enable RedPath CI"
git push origin main
```

The workflow has independent backend and frontend version-matrix jobs, a migration and documentation consistency gate, repository hygiene checks, and a container build/vulnerability gate. Backend jobs cover Python 3.11 and 3.12 with dependency consistency, the full Pytest suite, Ruff, Bandit, compilation, and strict `pip-audit`. Frontend jobs cover Node.js 20 and 22 with `npm ci --ignore-scripts`, Vitest, TypeScript checking, production builds, and high-severity production-dependency audits. The migration gate validates the additive tenant migration runner in a temporary SQLite database, runs migration regression tests, and checks public documentation links and API paths. The repository gate checks whitespace, tracked secret patterns, Compose syntax, and Dockerfile linting. The container gate builds both demo images and fails on High or Critical Trivy findings with available fixes.

| Gate | Matrix or scope | Control | Failure behavior |
| --- | --- | --- | --- |
| Backend | Python 3.11 and 3.12 | Tests, Ruff, Bandit, compilation, `pip check`, `pip-audit` | Blocks the job |
| Frontend | Node.js 20 and 22 | Vitest, TypeScript, build, `npm audit` | Blocks the job |
| Migrations and docs | Repository default versions | Idempotent migration smoke check, migration regression tests, local-link/API-path/public-naming checks | Blocks the job |
| Repository | Single repository job | Secret-pattern scan, Compose validation, Hadolint, whitespace check | Blocks the job |
| Containers | After all quality gates | Reproducible build with `--pull`, Trivy High/Critical scan | Blocks the job |

Every job has a timeout, the workflow has least-privilege read permissions by default, and pushes or pull requests cancel superseded runs. The container job requests `security-events: write` only for its own job so future SARIF reporting can be enabled without broadening repository permissions.

## Deterministic local verification

Run the same deterministic repository checks before opening a pull request:

```bash
./ci/quality-gate.sh
```

The local script runs backend tests, linting, Bandit, compilation, frontend clean installation/tests/type-check/build, whitespace validation, migration checks, documentation checks, Compose validation, and tracked secret-pattern checks. It expects Python dependencies from `backend/requirements.txt`, Node.js/npm, and Docker Compose. Hosted-only dependency and image vulnerability gates remain in the CI workflow when the local environment cannot provide the corresponding service.

The focused checks can also be run independently from the repository root:

```bash
PYTHONPATH=backend python ci/check_migrations.py
PYTHONPATH=backend python ci/check_docs.py
```

The migration check uses a temporary SQLite database only. It runs the existing additive migration runner twice, confirms the version table is stable, verifies the reserved legacy tenant backfill, and checks that tenant-bearing tables retain their `tenant_id` column. It never opens or mutates a project database.

The documentation check verifies required release files, relative local links, documented API paths against the FastAPI route table, required quality commands, and the absence of internal planning identifiers from user-facing documentation and frontend source.

## Branch protection and release handoff

Protect the default branch and require pull requests for all changes. Require the complete CI workflow to pass before merge, including both backend matrix entries, both frontend matrix entries, migration/documentation consistency, repository hygiene, and the container vulnerability gate. Require at least one maintainer approval, dismiss stale approvals after new commits, require branches to be up to date before merge, and prevent force pushes and branch deletion. Keep workflow files and branch-protection settings restricted to maintainers.

Use environment-scoped credentials only in a separately reviewed deployment workflow. Do not place tokens in repository variables that are readable by pull requests, do not use pull-request code to deploy, and require explicit protected-environment approval for any future deployment action. CI is validation-only and must not run network discovery, mutate SIEM systems, modify directory services, or perform remote actions.

## Secure container defaults

The backend image runs as UID/GID `10001`, does not retain pip caches, includes a liveness health check, and exposes only port `8000`. The demo console is built in a separate Node stage and served by the unprivileged nginx image on port `8080`. The Compose demo profile makes both services read-only, drops all Linux capabilities, enables `no-new-privileges`, limits process and memory counts, and allocates writable storage only for the API’s SQLite/audit data and required nginx temporary paths. The demo API also hard-codes dry-run mode and documentation-safe CIDRs.

These defaults are defense-in-depth rather than a substitute for server-side authorization, tenant isolation, server-derived actor identity, audit integrity, or network policy. Production deployments should provide an authenticated ingress, TLS, a managed database, a secret manager, and a dedicated metrics collector.
