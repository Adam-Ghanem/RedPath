"""Generate a release-candidate evidence manifest from the current checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_FILES = (
    "ci/redpath-ci.yml",
    "ci/quality-gate.sh",
    "ci/release-verify.sh",
    "ci/release_verify.py",
    "ci/check_environment.py",
    "ci/check_migrations.py",
    "ci/check_provenance.py",
    "ci/release_evidence.py",
    "docs/branch-protection.md",
    "docs/backup-restore-drill.md",
    "docs/incident-drills.md",
    "docs/release-operations.md",
    "docs/slo-reporting.md",
    "docs/migrations.md",
    "backend/Dockerfile",
    "frontend/Dockerfile.demo",
    "docker-compose.yml",
)
SBOM_REFERENCES = (
    "sbom-backend.spdx.json",
    "sbom-frontend.spdx.json",
    "pip-audit.json",
    "frontend/npm-audit.json",
)
VERIFICATION_COMMANDS = (
    "PYTHONPATH=backend python ci/check_environment.py --profile lab",
    "PYTHONPATH=backend python ci/check_migrations.py",
    "PYTHONPATH=backend python ci/migration_rehearsal.py",
    "PYTHONPATH=backend python ci/check_docs.py",
    "PYTHONPATH=backend python ci/release_verify.py",
    "PYTHONPATH=backend python ci/verify_backup.py --self-test",
    "PYTHONPATH=backend python ci/incident_drill.py --all",
    "PYTHONPATH=backend python ci/report_slo.py --input ci/fixtures/slo-sample.json",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def generate(output_path: Path) -> None:
    files = []
    for relative_path in RELEASE_FILES:
        path = REPO_ROOT / relative_path
        if not path.is_file():
            raise RuntimeError(f"release evidence file is missing: {relative_path}")
        files.append({"path": relative_path, "sha256": sha256(path)})

    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch:
        generated_at = datetime.fromtimestamp(int(source_date_epoch), tz=UTC)
    else:
        generated_at = datetime.now(tz=UTC)
    manifest = {
        "schema_version": "redpath-release-evidence/v1",
        "commit_sha": git_head(),
        "generated_at_utc": generated_at.isoformat().replace("+00:00", "Z"),
        "validation_only": True,
        "files": files,
        "sbom_references": list(SBOM_REFERENCES),
        "verification_commands": list(VERIFICATION_COMMANDS),
    }
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        generate(args.output)
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
        print(f"Release evidence generation failed safely: {exc}")
        return 1
    print(f"Release evidence manifest generated: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
