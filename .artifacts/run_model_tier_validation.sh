#!/usr/bin/env bash
set +e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.artifacts/model-tier-validation.log"
: > "$OUT"
run_gate() {
  local name="$1"
  shift
  {
    printf '\n=== %s ===\n' "$name"
    printf 'COMMAND: %q ' "$@"
    printf '\n'
    "$@"
    local code=$?
    printf 'EXIT_CODE: %s\n' "$code"
    return "$code"
  } >> "$OUT" 2>&1
}

run_gate backend_pytest bash -lc "cd '$ROOT/backend' && python3 -m pytest -q"
run_gate backend_ruff bash -lc "cd '$ROOT/backend' && ruff check ."
run_gate backend_bandit bash -lc "cd '$ROOT/backend' && bandit -q -r app"
run_gate backend_pip_audit bash -lc "cd '$ROOT/backend' && pip-audit -r requirements.txt"
run_gate frontend_npm_ci bash -lc "cd '$ROOT/frontend' && npm ci"
run_gate frontend_test bash -lc "cd '$ROOT/frontend' && npm run test -- --run"
run_gate frontend_build bash -lc "cd '$ROOT/frontend' && npm run build"
run_gate docs_check bash -lc "cd '$ROOT' && python3 ci/check_docs.py"

status=0
if grep -q '^EXIT_CODE: [1-9]' "$OUT"; then status=1; fi
printf '\nVALIDATION_STATUS: %s\n' "$status" | tee -a "$OUT"
exit "$status"
