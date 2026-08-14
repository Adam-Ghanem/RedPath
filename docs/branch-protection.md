# Branch protection and release safeguards

RedPath’s default branch should accept changes only through reviewed pull requests. This keeps security-sensitive contracts, tenant isolation, audit behavior, privacy boundaries, and dry-run behavior reviewable before release.

## Required repository settings

Enable branch protection on the default branch and require pull requests before merge. Require the branch to be up to date, require at least one maintainer approval, dismiss stale approvals after new commits, and prevent force pushes and branch deletion. Keep workflow files, protected environments, and branch-protection settings restricted to maintainers.

The required status checks should include the exact checks below. A check is required only when its job has completed successfully on the commit under review; do not accept a similarly named local or manually reported result.

| Required check | Control |
| --- | --- |
| `Backend quality (Python 3.11)` | Backend tests, lint, SAST, compilation, dependency consistency, and Python dependency audit |
| `Backend quality (Python 3.12)` | Cross-version backend quality parity |
| `Frontend quality (Node 20)` | Frontend tests, TypeScript quality, production build, and dependency audit |
| `Frontend quality (Node 22)` | Cross-version frontend quality parity |
| `Migration and documentation consistency` | Additive migration check, focused regression tests, links, API paths, and public naming |
| `Repository quality gates` | Whitespace, tracked secret-pattern scan, Compose validation, and Dockerfile linting |
| `SBOM and dependency review` | SPDX SBOM artifacts and pull-request dependency review |
| `Release assurance and recovery evidence` | Environment safety, migration rehearsal, backup verification, incident drills, SLO/error-budget report, evidence manifest, and provenance |
| `Container build and vulnerability gate` | Reproducible image builds and High/Critical vulnerability gate |
| `Release verification` | Required release files, secure runtime defaults, operational docs, and safe-failure controls |

Require CI artifacts to be retained according to repository policy, including the backend and frontend dependency reports, SPDX SBOMs, migration/docs output, release-assurance evidence, recovery/drill/SLO reports, release verification output, and container scan results. Do not treat an artifact as a secret store; reports must exclude credentials, raw telemetry, packet bytes, customer data, and unredacted identifiers.

## Release checklist

Before release, the maintainer should confirm that all required checks passed on the exact commit being released, dependency review has no unreviewed high-risk change, SBOMs were generated from the exact source and image digests, container hardening checks passed, and the release verification script succeeded. Database changes require a reviewed forward migration and compatible rollback or isolated-restore plan. The backup/restore drill design must be reviewed when persistence, retention, or deployment topology changes.

The release must preserve server-derived actor identity, tenant predicates, RBAC, audit-chain integrity, privacy redaction, dry-run defaults, and read-only external-system boundaries. Release notes and artifacts must contain no secrets, customer data, raw telemetry, or internal planning identifiers.

## Protected environments and safe failure

Do not allow pull-request code to deploy, access production credentials, or alter protected environments. Any future deployment workflow should use environment-scoped credentials, explicit protected-environment approval, and a separate review from validation-only CI. CI must not run network discovery, send packets, inject traffic, mutate SIEM or directory systems, execute arbitrary shell input, or perform destructive operations.

When a required check fails, stop promotion and preserve the diagnostic artifact. Do not bypass authentication, tenant predicates, audit logging, dry-run defaults, scope validation, or readiness checks to make a release green. Rollback selects a previously verified immutable artifact through the protected deployment process; it does not rewrite audit history or mutate external systems.

## Local verification

Run the deterministic repository gate from the repository root:

```bash
./ci/quality-gate.sh
./ci/release-verify.sh
```

When Docker is unavailable, run the focused non-container checks separately and record the limitation rather than weakening the hosted gate:

```bash
PYTHONPATH=backend python ci/check_migrations.py
PYTHONPATH=backend python ci/check_docs.py
PYTHONPATH=backend python ci/release_verify.py
PYTHONPATH=backend python ci/check_environment.py --profile lab
PYTHONPATH=backend python ci/migration_rehearsal.py
PYTHONPATH=backend python ci/verify_backup.py --self-test
PYTHONPATH=backend python ci/incident_drill.py --all --json
PYTHONPATH=backend python ci/report_slo.py --input ci/fixtures/slo-sample.json --json
```
