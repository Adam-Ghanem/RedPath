from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_check(script_name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "ci" / script_name)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_migration_check_command_is_deterministic() -> None:
    result = run_check("check_migrations.py")

    assert result.returncode == 0, result.stderr
    assert "idempotent" in result.stdout


def test_documentation_check_command_is_deterministic() -> None:
    result = run_check("check_docs.py")

    assert result.returncode == 0, result.stderr
    assert "public naming" in result.stdout


def test_release_verification_command_is_deterministic() -> None:
    result = run_check("release_verify.py")

    assert result.returncode == 0, result.stderr
    assert "required checks" in result.stdout
