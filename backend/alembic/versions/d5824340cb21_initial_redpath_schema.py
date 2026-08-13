"""Initial RedPath schema and legacy tenant backfill.

Revision ID: d5824340cb21
Revises:
Create Date: 2026-08-13
"""

import sqlalchemy as sa
from alembic import op
from app.db.models import Base, utcnow

revision = "d5824340cb21"
down_revision = None
branch_labels = None
depends_on = None

_TENANT_TABLES = (
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
    "case_governance_events",
    "assessment_runs",
    "purple_runs",
    "detection_observations",
    "audit_events",
)


def upgrade() -> None:
    """Create current tables and non-destructively add tenant isolation to legacy tables."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    inspector = sa.inspect(bind)

    for table_name in _TENANT_TABLES:
        if table_name not in inspector.get_table_names():
            continue
        columns = {column["name"] for column in inspector.get_columns(table_name)}
        if "tenant_id" not in columns:
            op.execute(  # nosec B608 - fixed internal table allowlist.
                sa.text(f'ALTER TABLE "{table_name}" ADD COLUMN tenant_id VARCHAR(128)')
            )
        bind.execute(  # nosec B608 - fixed internal table allowlist.
            sa.text(f'UPDATE "{table_name}" SET tenant_id = :tenant_id WHERE tenant_id IS NULL'),
            {"tenant_id": "legacy"},
        )

    bind.execute(
        sa.text(
            "INSERT INTO tenants (id, slug, name, is_active, created_at) "
            "SELECT 'legacy', 'legacy', 'Legacy imported records', 1, :created_at "
            "WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id = 'legacy')"
        ),
        {"created_at": utcnow()},
    )


def downgrade() -> None:
    """Return an Alembic-managed database to the pre-RedPath empty state."""
    Base.metadata.drop_all(bind=op.get_bind())
