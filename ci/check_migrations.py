"""Validate RedPath's local additive migration contract without touching a repository database."""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.db.models import Base, run_migrations  # noqa: E402

MIGRATIONS_DIR = REPO_ROOT / "backend" / "migrations"
DESTRUCTIVE_DDL = re.compile(r"\b(?:DROP\s+(?:TABLE|COLUMN|DATABASE)|TRUNCATE)\b", re.IGNORECASE)

TENANT_TABLES = (
    "scan_runs",
    "assets",
    "findings",
    "graph_nodes",
    "graph_edges",
    "campaigns",
    "campaign_run_links",
    "evidence_items",
    "remediation_items",
    "risk_acceptances",
    "assessment_runs",
    "purple_runs",
    "detection_observations",
    "audit_events",
)


def validate_sql_migrations() -> None:
    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not migration_files:
        raise RuntimeError("no SQL migration artifacts found")
    for migration_file in migration_files:
        content = migration_file.read_text(encoding="utf-8")
        if not re.search(r"\b(?:CREATE\s+(?:TABLE|INDEX)|ALTER\s+TABLE)\b", content, re.IGNORECASE):
            raise RuntimeError(f"migration has no additive DDL statement: {migration_file.name}")
        if DESTRUCTIVE_DDL.search(content):
            raise RuntimeError(f"migration contains destructive DDL: {migration_file.name}")


def validate_migrations() -> None:
    """Run the current migration runner twice and validate its stable end state."""
    with tempfile.TemporaryDirectory(prefix="redpath-migration-") as temporary_directory:
        database_path = Path(temporary_directory) / "redpath.db"
        engine = create_engine(f"sqlite:///{database_path}")
        Base.metadata.create_all(engine)
        run_migrations(engine)
        run_migrations(engine)

        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        required_tables = set(Base.metadata.tables) | {"schema_migrations"}
        missing_tables = sorted(required_tables - tables)
        if missing_tables:
            raise RuntimeError(f"migration check missing tables: {', '.join(missing_tables)}")

        missing_tenant_columns = [
            table_name
            for table_name in TENANT_TABLES
            if table_name in tables
            and "tenant_id" not in {column["name"] for column in inspector.get_columns(table_name)}
        ]
        if missing_tenant_columns:
            raise RuntimeError(
                "migration check missing tenant columns: " + ", ".join(missing_tenant_columns)
            )

        with engine.connect() as connection:
            versions = [
                row[0]
                for row in connection.execute(
                    text("SELECT version FROM schema_migrations ORDER BY version")
                )
            ]
            if versions != [2, 3, 4]:
                raise RuntimeError(f"unexpected schema migration versions: {versions!r}")
            legacy_tenant = connection.execute(
                text("SELECT id FROM tenants WHERE id = 'legacy'")
            ).scalar_one_or_none()
            if legacy_tenant != "legacy":
                raise RuntimeError("legacy tenant backfill is missing")


def main() -> int:
    validate_sql_migrations()
    validate_migrations()
    print("Migration checks passed: schema is additive, tenant-scoped, and idempotent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
