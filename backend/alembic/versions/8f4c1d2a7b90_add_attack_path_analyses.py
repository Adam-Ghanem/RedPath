"""add tenant-scoped attack path analysis registry

Revision ID: 8f4c1d2a7b90
Revises: d5824340cb21
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from alembic import op

revision = "8f4c1d2a7b90"
down_revision = "d5824340cb21"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "attack_path_analyses" not in inspector.get_table_names():
        op.create_table(
            "attack_path_analyses",
            sa.Column("id", sa.String(length=128), nullable=False),
            sa.Column("tenant_id", sa.String(length=128), nullable=False),
            sa.Column("actor_id", sa.String(length=128), nullable=False),
            sa.Column("graph_fingerprint", sa.String(length=64), nullable=False),
            sa.Column("summary_json", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        inspector = sa.inspect(bind)
    existing_indexes = {index["name"] for index in inspector.get_indexes("attack_path_analyses")}
    if "ix_attack_path_analyses_tenant_id" not in existing_indexes:
        op.create_index(
            "ix_attack_path_analyses_tenant_id",
            "attack_path_analyses",
            ["tenant_id"],
            unique=False,
        )
    if "ix_attack_path_analyses_graph_fingerprint" not in existing_indexes:
        op.create_index(
            "ix_attack_path_analyses_graph_fingerprint",
            "attack_path_analyses",
            ["graph_fingerprint"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index("ix_attack_path_analyses_graph_fingerprint", table_name="attack_path_analyses")
    op.drop_index("ix_attack_path_analyses_tenant_id", table_name="attack_path_analyses")
    op.drop_table("attack_path_analyses")
