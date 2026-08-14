from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_VERSIONS_DIR = REPO_ROOT / "backend" / "alembic" / "versions"
ROLLBACK_DOC = REPO_ROOT / "docs" / "migrations.md"


def test_alembic_is_the_only_migration_artifact_source() -> None:
    migration_files = sorted(path for path in ALEMBIC_VERSIONS_DIR.glob("*.py") if path.name != "__init__.py")
    assert migration_files
    for migration_file in migration_files:
        content = migration_file.read_text(encoding="utf-8")
        assert "revision =" in content
        assert "def upgrade" in content
        assert "def downgrade" in content
    assert not (REPO_ROOT / "backend" / "migrations").exists()
    assert "schema_migrations" not in "\n".join(
        path.read_text(encoding="utf-8") for path in migration_files
    )


def test_rollback_documentation_is_present_and_non_destructive() -> None:
    content = ROLLBACK_DOC.read_text(encoding="utf-8").lower()
    assert "## forward migration" in content
    assert "## rollback" in content
    assert "## validation" in content
    assert "drop table" not in content
    assert "drop column" not in content
