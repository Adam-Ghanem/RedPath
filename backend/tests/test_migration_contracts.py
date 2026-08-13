from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "backend" / "migrations"
ROLLBACK_DOC = REPO_ROOT / "docs" / "migrations.md"
FILENAME_PATTERN = re.compile(r"^\d{3}_[a-z0-9][a-z0-9_]*\.sql$")
DESTRUCTIVE_DDL = re.compile(r"\b(?:DROP\s+(?:TABLE|COLUMN|DATABASE)|TRUNCATE)\b", re.IGNORECASE)


def test_migration_artifacts_are_numbered_additive_and_non_destructive() -> None:
    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    assert migration_files
    for migration_file in migration_files:
        content = migration_file.read_text(encoding="utf-8")
        assert FILENAME_PATTERN.fullmatch(migration_file.name)
        assert re.search(r"\b(?:CREATE\s+(?:TABLE|INDEX)|ALTER\s+TABLE)\b", content, re.IGNORECASE)
        assert DESTRUCTIVE_DDL.search(content) is None


def test_rollback_documentation_is_present_and_non_destructive() -> None:
    content = ROLLBACK_DOC.read_text(encoding="utf-8").lower()
    assert "## forward migration" in content
    assert "## rollback" in content
    assert "## validation" in content
    assert "drop table" not in content
    assert "drop column" not in content
