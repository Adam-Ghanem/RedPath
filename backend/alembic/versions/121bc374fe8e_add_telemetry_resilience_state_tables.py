"""add telemetry resilience state tables

Revision ID: 121bc374fe8e
Revises: 935b0b17b45c
Create Date: 2026-08-14 02:28:19.095020
"""
from alembic import op
import sqlalchemy as sa

revision = '121bc374fe8e'
down_revision = '935b0b17b45c'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create tenant-scoped connector recovery records when absent."""
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "telemetry_ingestion_state" not in tables:
        op.create_table(
            "telemetry_ingestion_state",
            sa.Column("id", sa.String(length=192), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("source", sa.String(length=32), nullable=False, server_default="wazuh"),
            sa.Column("checkpoint_cursor", sa.Text(), nullable=True),
            sa.Column("cursor_version", sa.String(length=16), nullable=True),
            sa.Column("schema_version", sa.String(length=64), nullable=True),
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_lag_seconds", sa.Float(), nullable=True),
            sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("schema_drift_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error_code", sa.String(length=64), nullable=True),
            sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_telemetry_ingestion_state_tenant_id", "telemetry_ingestion_state", ["tenant_id"])
    if "telemetry_dead_letters" not in tables:
        op.create_table(
            "telemetry_dead_letters",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("source", sa.String(length=32), nullable=False, server_default="wazuh"),
            sa.Column("error_code", sa.String(length=64), nullable=False),
            sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("metadata_json", sa.JSON(), nullable=False),
            sa.Column("retry_after_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_telemetry_dead_letters_tenant_id", "telemetry_dead_letters", ["tenant_id"])
        op.create_index("ix_telemetry_dead_letters_error_code", "telemetry_dead_letters", ["error_code"])
        op.create_index("ix_telemetry_dead_letters_retry_after_at", "telemetry_dead_letters", ["retry_after_at"])
        op.create_index("ix_telemetry_dead_letters_expires_at", "telemetry_dead_letters", ["expires_at"])


def downgrade() -> None:
    """Remove only connector recovery tables introduced by this revision."""
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "telemetry_dead_letters" in tables:
        op.drop_table("telemetry_dead_letters")
    if "telemetry_ingestion_state" in tables:
        op.drop_table("telemetry_ingestion_state")
