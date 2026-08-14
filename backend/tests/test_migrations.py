from __future__ import annotations

from pathlib import Path

from app.db.models import Campaign, create_session_factory, run_alembic_downgrade, run_alembic_migrations
from sqlalchemy import create_engine, inspect, text


def test_additive_migration_backfills_legacy_tenant(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{database_path}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE campaigns ("
                "id VARCHAR(36) PRIMARY KEY, "
                "name VARCHAR(255) NOT NULL, "
                "objective TEXT NOT NULL, "
                "owner VARCHAR(128) NOT NULL, "
                "status VARCHAR(32) NOT NULL, "
                "scope_snapshot JSON NOT NULL, "
                "created_at DATETIME NOT NULL, "
                "updated_at DATETIME NOT NULL"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO campaigns "
                "(id, name, objective, owner, status, scope_snapshot, created_at, updated_at) "
                "VALUES ('legacy-campaign', 'Legacy', 'Imported fixture', 'legacy', 'active', '[]', "
                "'2026-08-13T00:00:00+00:00', '2026-08-13T00:00:00+00:00')"
            )
        )

    session_factory = create_session_factory(f"sqlite:///{database_path}")
    assert "tenant_id" in {column["name"] for column in inspect(engine).get_columns("campaigns")}
    with session_factory() as session:
        row = session.get(Campaign, "legacy-campaign")
        assert row is not None
        assert row.tenant_id == "legacy"


def test_attack_path_analysis_alembic_upgrade_downgrade_reupgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'attack-path-lifecycle.db'}"
    run_alembic_migrations(database_url)
    engine = create_engine(database_url)
    assert "attack_path_analyses" in inspect(engine).get_table_names()

    run_alembic_downgrade(database_url, "d5824340cb21")
    assert "attack_path_analyses" not in inspect(engine).get_table_names()

    run_alembic_migrations(database_url)
    run_alembic_migrations(database_url)
    assert "attack_path_analyses" in inspect(engine).get_table_names()
