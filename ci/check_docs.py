"""Validate public documentation against local routes and release commands."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.main import app  # noqa: E402

DOCUMENTED_ENDPOINT = re.compile(r"`(/api/v1/[^`\s]+)`")
LOCAL_LINK = re.compile(r"\]\((?!https?://|#)([^)]+)\)")
INTERNAL_IDENTIFIER = re.compile(r"\b(?:AI|ai)-\d+\b|\bworkstream\b")
USER_FACING_PATHS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CONTRIBUTING.md",
    REPO_ROOT / "docs",
    REPO_ROOT / "frontend" / "src",
)
REQUIRED_FILES = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CONTRIBUTING.md",
    REPO_ROOT / "docs" / "api.md",
    REPO_ROOT / "docs" / "branch-protection.md",
    REPO_ROOT / "docs" / "ci-setup.md",
    REPO_ROOT / "docs" / "database.md",
    REPO_ROOT / "ci" / "quality-gate.sh",
    REPO_ROOT / "ci" / "check_migrations.py",
)
REQUIRED_COMMANDS = (
    "./ci/quality-gate.sh",
    "python ci/check_migrations.py",
    "python ci/check_docs.py",
)


def iter_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(item for item in path.rglob("*") if item.is_file())


def without_fenced_code(content: str) -> str:
    lines: list[str] = []
    in_fence = False
    for line in content.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return "\n".join(lines)


def validate_required_files() -> None:
    missing = [str(path.relative_to(REPO_ROOT)) for path in REQUIRED_FILES if not path.is_file()]
    if missing:
        raise RuntimeError("missing release documentation or check files: " + ", ".join(missing))


def validate_local_links() -> None:
    broken: list[str] = []
    for root in USER_FACING_PATHS:
        for path in iter_files(root):
            if path.suffix.lower() not in {".md", ".tsx", ".ts"}:
                continue
            content = without_fenced_code(path.read_text(encoding="utf-8"))
            for target in LOCAL_LINK.findall(content):
                target_path = target.split("#", 1)[0].strip()
                if not target_path or target_path.startswith("mailto:"):
                    continue
                resolved = (path.parent / target_path).resolve()
                if not resolved.exists():
                    broken.append(f"{path.relative_to(REPO_ROOT)} -> {target_path}")
    if broken:
        raise RuntimeError("broken local documentation links: " + "; ".join(sorted(broken)))


def validate_api_documentation() -> None:
    documented = set(DOCUMENTED_ENDPOINT.findall((REPO_ROOT / "docs" / "api.md").read_text(encoding="utf-8")))
    route_paths = {
        path
        for path in app.openapi().get("paths", {})
        if path.startswith("/api/")
    }
    missing = sorted(documented - route_paths)
    if missing:
        raise RuntimeError("documented API paths missing from FastAPI routes: " + ", ".join(missing))


def validate_release_commands() -> None:
    ci_setup = (REPO_ROOT / "docs" / "ci-setup.md").read_text(encoding="utf-8")
    missing = [command for command in REQUIRED_COMMANDS if command not in ci_setup]
    if missing:
        raise RuntimeError("CI setup documentation is missing commands: " + ", ".join(missing))


def validate_public_identifier_boundary() -> None:
    matches: list[str] = []
    for root in USER_FACING_PATHS:
        for path in iter_files(root):
            if path.suffix.lower() not in {".md", ".tsx", ".ts"}:
                continue
            content = path.read_text(encoding="utf-8")
            if INTERNAL_IDENTIFIER.search(content):
                matches.append(str(path.relative_to(REPO_ROOT)))
    if matches:
        raise RuntimeError(
            "internal workstream identifiers found in user-facing files: " + ", ".join(sorted(matches))
        )


def main() -> int:
    validate_required_files()
    validate_local_links()
    validate_api_documentation()
    validate_release_commands()
    validate_public_identifier_boundary()
    print("Documentation checks passed: links, API paths, release commands, and public naming are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
