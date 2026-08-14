"""Rehearse the Alembic lifecycle in an isolated temporary SQLite database."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.db.models import run_alembic_downgrade, run_alembic_migrations  # noqa: E402

DOWNGRADE_TARGET = "d5824340cb21"


def rehearse() -> None:
    with tempfile.TemporaryDirectory(prefix="redpath-migration-rehearsal-") as directory:
        database_url = f"sqlite:///{Path(directory) / 'rehearsal.db'}"
        run_alembic_migrations(database_url)
        run_alembic_migrations(database_url)

        engine = create_engine(database_url)
        with engine.connect() as connection:
            before_downgrade = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        if not before_downgrade:
            raise RuntimeError("upgrade did not produce an Alembic head revision")

        run_alembic_downgrade(database_url, DOWNGRADE_TARGET)
        downgraded_tables = set(inspect(create_engine(database_url)).get_table_names())
        if "attack_path_analyses" in downgraded_tables:
            raise RuntimeError("downgrade rehearsal left attack_path_analyses in place")

        run_alembic_migrations(database_url)
        run_alembic_migrations(database_url)
        final_engine = create_engine(database_url)
        final_tables = set(inspect(final_engine).get_table_names())
        required_tables = {"alembic_version", "tenants", "audit_events", "attack_path_analyses"}
        if not required_tables.issubset(final_tables):
            missing = sorted(required_tables - final_tables)
            raise RuntimeError("re-upgrade rehearsal is missing tables: " + ", ".join(missing))
        with final_engine.connect() as connection:
            final_revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            legacy_tenant = connection.execute(text("SELECT id FROM tenants WHERE id = 'legacy'")).scalar_one_or_none()
        if not final_revision or legacy_tenant != "legacy":
            raise RuntimeError("re-upgrade rehearsal did not restore the tenant-scoped head state")


def main() -> int:
    try:
        rehearse()
    except Exception as exc:  # pragma: no cover - CLI failure path is asserted by exit code
        print(f"Migration rehearsal failed safely: {exc}")
        return 1
    print("Migration rehearsal passed: upgrade, downgrade, re-upgrade, and tenant/audit checks are isolated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
