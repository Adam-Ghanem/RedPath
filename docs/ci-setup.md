# CI workflow activation

The canonical CI definition is `ci/redpath-ci.yml`. It is stored outside `.github/workflows/` so it can be pushed by repositories whose GitHub App token does not have the special workflow permission.

To activate GitHub Actions later, an administrator with repository write access should copy the file to `.github/workflows/ci.yml` through the GitHub web editor or a local clone, then commit it:

```bash
mkdir -p .github/workflows
cp ci/redpath-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "Enable RedPath CI"
git push origin main
```

The workflow runs backend Pytest, Ruff, Bandit, Semgrep, and frontend TypeScript/build checks. GitHub treats files under `.github/workflows/` as executable workflow configuration, which is why a token must have the dedicated workflow permission for an API or Git push to create that path. The copy under `ci/` remains inert configuration until an authorized repository maintainer activates it.
