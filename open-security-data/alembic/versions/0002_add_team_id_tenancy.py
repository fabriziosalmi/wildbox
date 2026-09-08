"""Add the tenancy columns that create_all() could never add.

Revision ID: 0002_team_id
Revises: 0001_baseline
Create Date: 2026-09-08

sources.team_id and indicators.team_id were added to app/models.py in commit
48c953d, long after the tables were first created. Because the service built its
schema with Base.metadata.create_all() -- which emits CREATE TABLE and never
ALTER TABLE -- any database created before that commit still lacks the columns,
and every tenancy-scoped query against it fails with UndefinedColumn at runtime
(WILDBO-DOM-01).

NULL means a global/shared feed, visible to every team, which is the documented
semantics in app/models.py, so existing rows keep their current behaviour.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_team_id"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column in {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    # Idempotent: a database created after 48c953d already has these columns
    # because create_all() built them from the models.
    if not _has_column("sources", "team_id"):
        op.add_column(
            "sources",
            sa.Column("team_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.create_index("ix_sources_team_id", "sources", ["team_id"])

    if not _has_column("indicators", "team_id"):
        op.add_column(
            "indicators",
            sa.Column("team_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.create_index("ix_indicators_team_id", "indicators", ["team_id"])


def downgrade() -> None:
    if _has_column("indicators", "team_id"):
        op.drop_index("ix_indicators_team_id", table_name="indicators")
        op.drop_column("indicators", "team_id")
    if _has_column("sources", "team_id"):
        op.drop_index("ix_sources_team_id", table_name="sources")
        op.drop_column("sources", "team_id")
