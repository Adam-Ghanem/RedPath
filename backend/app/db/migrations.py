from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

SCHEMA_VERSION = 2


def migrate(engine: Engine) -> None:
    """Apply additive, idempotent migrations required by the governance slice.

    The prototype uses SQLAlchemy metadata creation for new tables. This migration
    keeps existing SQLite files compatible when a new nullable column is added to
    the remediation table; it never drops data or rewrites user evidence.
    """

    inspector = inspect(engine)
    remediation_columns = {column["name"] for column in inspector.get_columns("remediation_items")}
    if "verification_evidence_id" not in remediation_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE remediation_items ADD COLUMN verification_evidence_id VARCHAR(36)"))
