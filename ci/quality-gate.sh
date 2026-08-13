#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '%s\n' '== Backend: tests, lint, security, compile =='
(
  cd "$repo_root/backend"
  python -m pip check
  PYTHONPATH=. pytest -q
  ruff check app tests
  bandit -r app -ll
  python -m compileall -q app
)

printf '%s\n' '== Frontend: tests, typecheck, build =='
(
  cd "$repo_root/frontend"
  npm ci --ignore-scripts
  npm run test -- --run
  npm run lint
  npm run build
)

printf '%s\n' '== Repository: whitespace, compose, secret patterns =='
(
  cd "$repo_root"
  git diff --check
  docker compose config --quiet
  if git grep -n -I -E '(AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,})' -- . ':!docs/github-metadata.md'; then
    printf '%s\n' 'Potential secret pattern found in tracked files.' >&2
    exit 1
  fi
)

printf '%s\n' 'All local RedPath quality gates passed.'
