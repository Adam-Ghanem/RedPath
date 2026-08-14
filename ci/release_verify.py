"""Validate release assurance controls without contacting external systems."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
USER_FACING_ROOTS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CONTRIBUTING.md",
    REPO_ROOT / "docs",
    REPO_ROOT / "frontend" / "src",
)
INTERNAL_IDENTIFIER = re.compile(r"\b(?:AI|ai)-\d+\b|\bworkstream\b")


def read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def require_fragments(relative_path: str, fragments: tuple[str, ...]) -> None:
    content = read(relative_path)
    folded_content = content.casefold()
    missing = [fragment for fragment in fragments if fragment.casefold() not in folded_content]
    if missing:
        raise RuntimeError(
            f"{relative_path} is missing required release controls: {', '.join(missing)}"
        )


def iter_user_facing_files() -> list[Path]:
    files: list[Path] = []
    for root in USER_FACING_ROOTS:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix.lower() in {".md", ".tsx", ".ts"}
            )
    return sorted(files)


def validate_workflow() -> None:
    require_fragments(
        "ci/redpath-ci.yml",
        (
            "backend:",
            "frontend:",
            "migration_docs:",
            "repository:",
            "containers:",
            "dependency_review:",
            "release_assurance:",
            "release_verify:",
            "actions/upload-artifact@v4",
            "actions/download-artifact@v4",
            "actions/dependency-review-action@v4",
            "anchore/sbom-action@v0.18.0",
            "check_environment.py --profile lab",
            "migration_rehearsal.py",
            "verify_backup.py --self-test",
            "incident_drill.py --all --json",
            "report_slo.py --input ci/fixtures/slo-sample.json --json",
            "release_evidence.py --output release-evidence.json",
            "check_provenance.py release-evidence.json",
            "retention-days: 30",
            "permissions:\n  contents: read",
        ),
    )


def validate_runtime_hardening() -> None:
    require_fragments(
        "backend/Dockerfile",
        (
            "USER 10001:10001",
            "HEALTHCHECK",
            'ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0"',
        ),
    )
    require_fragments(
        "frontend/Dockerfile.demo",
        ("nginxinc/nginx-unprivileged", "EXPOSE 8080", "HEALTHCHECK"),
    )
    require_fragments(
        "docker-compose.yml",
        ("read_only: true", "cap_drop:", "no-new-privileges:true", "pids_limit:", "mem_limit:"),
    )
    compose = read("docker-compose.yml")
    if "privileged: true" in compose or "network_mode: host" in compose:
        raise RuntimeError("unsafe privileged or host-network runtime setting found")


def validate_operations_docs() -> None:
    required_files = (
        "docs/backup-restore-drill.md",
        "docs/incident-drills.md",
        "docs/migrations.md",
        "docs/release-operations.md",
        "docs/slo-reporting.md",
        "docs/branch-protection.md",
        "docs/observability.md",
    )
    missing = [path for path in required_files if not (REPO_ROOT / path).is_file()]
    if missing:
        raise RuntimeError("missing operations documentation: " + ", ".join(missing))
    require_fragments(
        "docs/backup-restore-drill.md",
        ("RPO", "RTO", "isolated restore", "tenant isolation", "audit", "verify_backup.py"),
    )
    require_fragments(
        "docs/release-operations.md",
        ("SLO", "structured logs", "metrics", "traces", "safe failure", "runbook", "evidence manifest", "error budget"),
    )
    require_fragments(
        "docs/branch-protection.md",
        ("dependency review", "SBOM", "release verification", "required check"),
    )
    require_fragments("docs/incident-drills.md", ("approval-gated", "safe response", "tenant/RBAC", "fails closed"))
    require_fragments("docs/slo-reporting.md", ("error-budget", "pause_promotion", "aggregate counters"))
    require_fragments("docs/migrations.md", ("migration_rehearsal.py", "downgrade", "no table"))


def validate_public_naming() -> None:
    matches = [
        str(path.relative_to(REPO_ROOT))
        for path in iter_user_facing_files()
        if INTERNAL_IDENTIFIER.search(path.read_text(encoding="utf-8"))
    ]
    if matches:
        raise RuntimeError("internal planning identifiers found in user-facing files: " + ", ".join(matches))


def main() -> int:
    validate_workflow()
    validate_runtime_hardening()
    validate_operations_docs()
    validate_public_naming()
    print("Release verification passed: required checks, artifacts, hardening, and operations docs are present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
