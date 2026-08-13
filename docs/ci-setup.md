# CI and release-quality setup

RedPath’s canonical quality pipeline is `ci/redpath-ci.yml`. It is intentionally stored outside `.github/workflows/` because repository workflow activation requires the dedicated GitHub workflow permission. A repository maintainer can activate it with the following one-time command from a clone that has that permission:

```bash
mkdir -p .github/workflows
cp ci/redpath-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "Enable RedPath CI"
git push origin main
```

The workflow has independent backend and frontend version-matrix jobs, migration and documentation consistency, repository hygiene, SBOM/dependency review, container vulnerability, and release-verification gates. Backend jobs cover Python 3.11 and 3.12 with dependency consistency, Pytest, Ruff, Bandit, compilation, and strict `pip-audit`. Frontend jobs cover Node.js 20 and 22 with `npm ci --ignore-scripts`, Vitest, TypeScript checking, production builds, and high-severity production-dependency audits. The migration gate validates the additive tenant migration runner in a temporary SQLite database, runs migration regression tests, and checks public documentation links and API paths. The repository gate checks whitespace, tracked secret patterns, Compose syntax, and Dockerfile linting.

The SBOM/dependency-review job runs pull-request dependency review, emits JSON dependency-audit reports, and generates SPDX JSON SBOMs for the backend and frontend source trees. These artifacts are attached to the exact workflow run with bounded retention and must not contain credentials, raw telemetry, packet bytes, or customer data. The container gate builds both demo images and fails on High or Critical Trivy findings with available fixes. The release-verification gate runs after the quality and container gates and verifies the required artifact, documentation, hardening, and safe-failure contracts.

| Required check | Control | Artifact or evidence |
| --- | --- | --- |
| `Backend quality (Python 3.11)` | Backend tests, lint, SAST, compilation, dependency consistency, and Python audit | Job log and audit result |
| `Backend quality (Python 3.12)` | Cross-version backend quality parity | Job log and audit result |
| `Frontend quality (Node 20)` | Frontend tests, TypeScript quality, build, and dependency audit | Job log and audit result |
| `Frontend quality (Node 22)` | Cross-version frontend quality parity | Job log and audit result |
| `Migration and documentation consistency` | Additive migration, focused tests, links, API paths, and public naming | Job log |
| `Repository quality gates` | Whitespace, tracked secret scan, Compose validation, and Dockerfile linting | Job log |
| `SBOM and dependency review` | Pull-request dependency review, JSON audits, and SPDX SBOMs | Retained audit/SBOM artifact |
| `Container build and vulnerability gate` | Reproducible image builds and High/Critical vulnerability gate | Container scan log |
| `Release verification` | Release files, hardening, operations docs, and safe-failure controls | Retained verification artifact |

Every job has a timeout, the workflow has least-privilege read permissions by default, and pushes or pull requests cancel superseded runs. The container job requests `security-events: write` only for its own job. Pull-request code is never deployed and no job performs network discovery, remote SIEM mutation, directory mutation, packet injection, or destructive action.

## Deterministic local verification

Run the deterministic repository gate from the repository root:

```bash
./ci/quality-gate.sh
./ci/release-verify.sh
```

The local gate runs backend tests, linting, Bandit, compilation, frontend clean installation/tests/type-check/build, migration checks, documentation checks, release verification, whitespace validation, Compose validation, and tracked secret-pattern checks. It expects Python dependencies from `backend/requirements.txt`, Node.js/npm, and Docker Compose. Hosted-only dependency review, SBOM generation, and image vulnerability checks remain in CI when the local environment cannot provide those services.

The focused checks can also be run independently:

```bash
PYTHONPATH=backend python ci/check_migrations.py
PYTHONPATH=backend python ci/check_docs.py
PYTHONPATH=backend python ci/release_verify.py
```

The migration check uses a temporary SQLite database only. It runs the existing additive migration runner twice, confirms the version table is stable, verifies the reserved legacy tenant backfill, checks tenant-bearing tables, and rejects destructive SQL migration statements. It never opens or mutates a project database.

The documentation check verifies required release files, relative local links, documented API paths against the FastAPI route table, required quality commands, and the absence of internal planning identifiers from user-facing documentation and frontend source. The release-verification check validates required CI jobs and actions, secure runtime defaults, operations documentation, recovery-drill design, and safe-failure guidance.

## Branch protection and release handoff

Protect the default branch and require pull requests for all changes. Require every status check listed above on the exact commit being merged, require at least one maintainer approval, dismiss stale approvals after new commits, require branches to be up to date, and prevent force pushes and branch deletion. Keep workflow files and branch-protection settings restricted to maintainers. See [`docs/branch-protection.md`](branch-protection.md).

Use environment-scoped credentials only in a separately reviewed deployment workflow. Do not place tokens in repository variables readable by pull requests, do not use pull-request code to deploy, and require explicit protected-environment approval for any future deployment action. Release operators should follow [`docs/release-operations.md`](release-operations.md) and review [`docs/backup-restore-drill.md`](backup-restore-drill.md) when persistence or topology changes.

## Secure container defaults

The backend image runs as UID/GID `10001`, does not retain pip caches, includes a liveness health check, and exposes only port `8000`. The demo console is built in a separate Node stage and served by the unprivileged nginx image on port `8080`. The Compose demo profile makes both services read-only, drops all Linux capabilities, enables `no-new-privileges`, limits process and memory counts, and allocates writable storage only for the API’s SQLite/audit data and required nginx temporary paths. The demo API also hard-codes dry-run mode and documentation-safe CIDRs.

These defaults are defense-in-depth rather than a substitute for server-side authorization, tenant isolation, server-derived actor identity, audit integrity, privacy redaction, or network policy. Production deployments should provide an authenticated ingress, TLS, a managed database, a secret manager, and a dedicated metrics collector.
