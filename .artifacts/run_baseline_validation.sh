#!/usr/bin/env bash
set +e
cd "$(dirname "$0")/.."
LOG=".artifacts/baseline-validation.log"
: > "$LOG"
run_step() {
  name="$1"
  shift
  printf '\n=== %s ===\n' "$name" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
  code=${PIPESTATUS[0]}
  printf 'EXIT_CODE[%s]=%s\n' "$name" "$code" | tee -a "$LOG"
}
run_step backend_pytest bash -lc 'cd backend && python3 -m pytest -q'
run_step backend_ruff bash -lc 'cd backend && ruff check .'
run_step backend_bandit bash -lc 'cd backend && bandit -q -r app'
run_step backend_pip_audit bash -lc 'cd backend && pip-audit -r requirements.txt'
run_step frontend_npm_ci bash -lc 'cd frontend && npm ci'
run_step frontend_npm_test bash -lc 'cd frontend && npm run test -- --run'
run_step frontend_npm_build bash -lc 'cd frontend && npm run build'
run_step docs_check python3 ci/check_docs.py
printf '\n=== BASELINE SUMMARY ===\n' | tee -a "$LOG"
grep '^EXIT_CODE' "$LOG" | tee -a "$LOG"
