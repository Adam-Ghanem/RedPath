"""add telemetry operational resilience state

Revision ID: 6f4a2b8c9d10
Revises: 4f2a6c1e9b77
"""

import sqlalchemy as sa
from alembic import op

revision = "6f4a2b8c9d10"
down_revision = "4f2a6c1e9b77"
branch_labels = None
depends_on = None


_COLUMNS = (
    ("circuit_state", sa.String(length=16), False, "closed"),
    ("circuit_open_until", sa.DateTime(timezone=True), True, None),
    ("capacity_window_started_at", sa.DateTime(timezone=True), True, None),
    ("capacity_events_reserved", sa.Integer(), False, "0"),
    ("capacity_bytes_reserved", sa.Integer(), False, "0"),
    ("last_attempt_at", sa.DateTime(timezone=True), True, None),
)


def upgrade() -> None:
    """Add bounded local operational state without touching telemetry events or remote sources."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "telemetry_ingestion_state" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("telemetry_ingestion_state")}
    for name, column_type, nullable, default in _COLUMNS:
        if name in existing:
            continue
        kwargs = {"nullable": nullable}
        if default is not None:
            kwargs["server_default"] = default
        op.add_column("telemetry_ingestion_state", sa.Column(name, column_type, **kwargs))


def downgrade() -> None:
    """Remove only the Phase 4 operational columns; preserve events, dead letters, and checkpoint history."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "telemetry_ingestion_state" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("telemetry_ingestion_state")}
    for name, _column_type, _nullable, _default in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("telemetry_ingestion_state", name)
