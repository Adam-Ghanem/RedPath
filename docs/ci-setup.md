# CI and quality gates

RedPath’s canonical quality pipeline is `ci/redpath-ci.yml`. It is intentionally stored outside `.github/workflows/` because repository workflow activation requires the dedicated GitHub workflow permission. A repository maintainer can activate it with the following one-time command from a clone that has that permission:

```bash
mkdir -p .github/workflows
cp ci/redpath-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "Enable RedPath CI"
git push origin main
```

The pipeline is divided into four gates. The backend gate runs dependency consistency checks, the full Pytest suite, Ruff, Bandit, Python compilation, and a strict `pip-audit` dependency review. The frontend gate uses `npm ci --ignore-scripts`, runs Vitest, TypeScript checking, the production build, and a high-severity production-dependency audit. The repository gate rejects whitespace errors, scans tracked files for common high-risk secret patterns, validates Compose syntax, and lints both Dockerfiles. The container gate builds both demo images and fails on unfixed High or Critical Trivy findings.

| Gate | Control | Failure behavior |
| --- | --- | --- |
| Backend | Tests, Ruff, Bandit, compile, `pip check`, `pip-audit` | Blocks the job |
| Frontend | Vitest, TypeScript, build, `npm audit` | Blocks the job |
| Repository | Secret-pattern scan, Compose validation, Hadolint | Blocks the job |
| Containers | Reproducible build with `--pull`, Trivy High/Critical scan | Blocks the job |

Every job has a timeout, the workflow has least-privilege read permissions by default, and pushes or pull requests cancel superseded runs. The container job requests `security-events: write` only for its own job so future SARIF reporting can be enabled without broadening repository permissions.

## Local execution

Run the same fast local checks before opening a pull request:

```bash
./ci/quality-gate.sh
```

The script expects Python dependencies from `backend/requirements.txt`, Node.js/npm, and Docker Compose. The CI-only dependency audit and image vulnerability scan remain in the hosted workflow because they require network and container services.

## Secure container defaults

The backend image runs as UID/GID `10001`, does not retain pip caches, includes a liveness health check, and exposes only port `8000`. The demo console is built in a separate Node stage and served by the unprivileged nginx image on port `8080`. The Compose demo profile makes both services read-only, drops all Linux capabilities, enables `no-new-privileges`, limits process and memory counts, and allocates writable storage only for the API’s SQLite/audit data and required nginx temporary paths. The demo API also hard-codes dry-run mode and documentation-safe CIDRs.

These defaults are defense-in-depth rather than a substitute for server-side authorization, tenant isolation, or network policy. Production deployments should provide an authenticated ingress, TLS, a managed database, a secret manager, and a dedicated metrics collector.
