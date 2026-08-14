"""Validate RedPath's local additive migration contract without touching a repository database."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.db.models import Base, run_alembic_downgrade, run_alembic_migrations  # noqa: E402

MIGRATIONS_DIR = REPO_ROOT / "backend" / "alembic" / "versions"

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
    "attack_path_analyses",
    "remediation_verification_evidence",
    "approval_delegations",
    "case_decision_events",
)


def validate_alembic_revisions() -> None:
    migration_files = sorted(path for path in MIGRATIONS_DIR.glob("*.py") if path.name != "__init__.py")
    if not migration_files:
        raise RuntimeError("no Alembic revision artifacts found")
    for migration_file in migration_files:
        content = migration_file.read_text(encoding="utf-8")
        if "revision =" not in content or "def upgrade" not in content or "def downgrade" not in content:
            raise RuntimeError(f"invalid Alembic revision: {migration_file.name}")


def validate_migrations() -> None:
    """Run the authoritative Alembic upgrade twice and validate its stable end state."""
    with tempfile.TemporaryDirectory(prefix="redpath-migration-") as temporary_directory:
        database_path = Path(temporary_directory) / "redpath.db"
        database_url = f"sqlite:///{database_path}"
        run_alembic_migrations(database_url)
        run_alembic_migrations(database_url)
        run_alembic_downgrade(database_url, "d5824340cb21")
        downgraded_engine = create_engine(database_url)
        downgraded_tables = set(inspect(downgraded_engine).get_table_names())
        if "attack_path_analyses" in downgraded_tables:
            raise RuntimeError("Alembic downgrade did not remove attack_path_analyses")
        run_alembic_migrations(database_url)
        run_alembic_migrations(database_url)
        engine = create_engine(database_url)
        inspector = inspect(engine)

        tables = set(inspector.get_table_names())
        required_tables = set(Base.metadata.tables) | {"alembic_version"}
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
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            if not revision:
                raise RuntimeError("Alembic head revision is missing")
            legacy_tenant = connection.execute(
                text("SELECT id FROM tenants WHERE id = 'legacy'")
            ).scalar_one_or_none()
            if legacy_tenant != "legacy":
                raise RuntimeError("legacy tenant backfill is missing")


def main() -> int:
    validate_alembic_revisions()
    validate_migrations()
    print(
        "Migration checks passed: upgrade=ok, downgrade=ok, re-upgrade=ok, "
        "Alembic schema is tenant-scoped and idempotent."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
