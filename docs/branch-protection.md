# Branch protection and release safeguards

RedPath’s default branch should accept changes only through reviewed pull requests. This keeps security-sensitive contracts, tenant isolation, audit behavior, and dry-run boundaries reviewable before release.

## Required repository settings

Enable branch protection on the default branch and require pull requests before merge. Require the complete CI workflow to pass, including backend quality on Python 3.11 and 3.12, frontend quality on Node.js 20 and 22, migration and documentation checks, repository hygiene, and the container vulnerability gate. Require at least one maintainer approval, dismiss stale approvals after new commits, require branches to be up to date before merge, and prevent force pushes and branch deletion.

Keep workflow files and branch-protection settings restricted to maintainers. Do not allow pull-request code to deploy, access production credentials, or alter protected environments. Any future deployment workflow should use environment-scoped credentials, explicit protected-environment approval, and a separate review from validation-only CI.

## Release checklist

Before release, the maintainer should confirm that the required checks passed on the exact commit being released, database changes have a reviewed forward migration and a compatible rollback plan, documentation checks pass, and the release notes contain no secrets, customer data, raw telemetry, or internal planning identifiers. The release must preserve server-derived actor identity, tenant predicates, RBAC, audit-chain integrity, dry-run defaults, and read-only external-system boundaries.

CI must remain validation-only. It must not run network discovery, send packets, inject traffic, mutate SIEM or directory systems, execute arbitrary shell input, or perform destructive operations. Container vulnerability findings and migration failures block release until fixed or explicitly reviewed under the repository’s security process.

## Local verification

Run the deterministic repository gate from the repository root:

```bash
./ci/quality-gate.sh
```

When Docker is unavailable, run the focused non-container checks separately and record the container limitation rather than weakening the CI gate:

```bash
PYTHONPATH=backend python ci/check_migrations.py
PYTHONPATH=backend python ci/check_docs.py
```
