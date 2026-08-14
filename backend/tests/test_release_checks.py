from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_check(script_name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "ci" / script_name), *arguments],
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


def test_environment_check_preserves_lab_safety() -> None:
    result = run_check("check_environment.py", "--profile", "lab")

    assert result.returncode == 0, result.stderr
    assert "secret values were not emitted" in result.stdout


def test_migration_rehearsal_is_isolated() -> None:
    result = run_check("migration_rehearsal.py")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "isolated" in result.stdout


def test_backup_and_incident_drills_are_read_only() -> None:
    backup = run_check("verify_backup.py", "--self-test")
    drills = run_check("incident_drill.py", "--all", "--json")

    assert backup.returncode == 0, backup.stdout + backup.stderr
    assert "redaction metadata" in backup.stdout
    assert drills.returncode == 0, drills.stdout + drills.stderr
    assert '"status": "pass"' in drills.stdout


def test_slo_report_has_bounded_error_budget() -> None:
    report = run_check(
        "report_slo.py",
        "--input",
        str(REPO_ROOT / "ci" / "fixtures" / "slo-sample.json"),
        "--json",
    )

    assert report.returncode == 0, report.stdout + report.stderr
    assert '"status": "pass"' in report.stdout
    assert '"error_budget_remaining_fraction": 0.6' in report.stdout


def test_slo_report_pauses_on_integrity_failure(tmp_path: Path) -> None:
    fixture = tmp_path / "slo-failure.json"
    fixture.write_text(
        json.dumps(
            {
                "window_minutes": 5,
                "requests_total": 100,
                "server_errors": 20,
                "ready_checks_total": 100,
                "ready_failures": 10,
                "latency_ms": [100, 200, 300],
                "audit_failures": 1,
                "tenant_boundary_failures": 0,
            }
        ),
        encoding="utf-8",
    )
    report = run_check("report_slo.py", "--input", str(fixture), "--json")

    assert report.returncode == 0, report.stdout + report.stderr
    assert '"status": "pause_promotion"' in report.stdout
    assert "pause promotion" in report.stdout


def test_release_evidence_round_trip_is_deterministic(tmp_path: Path) -> None:
    manifest = tmp_path / "release-evidence.json"
    generated = run_check("release_evidence.py", "--output", str(manifest))
    validated = run_check("check_provenance.py", str(manifest))

    assert generated.returncode == 0, generated.stdout + generated.stderr
    assert validated.returncode == 0, validated.stdout + validated.stderr
    assert "Provenance check passed" in validated.stdout
