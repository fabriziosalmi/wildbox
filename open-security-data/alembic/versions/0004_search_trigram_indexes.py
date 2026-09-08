"""Make the indicator free-text search indexable.

Revision ID: 0004_trgm
Revises: 0003_vocab
Create Date: 2026-09-08

The search endpoint ORs three leading-wildcard ILIKE comparisons across value,
normalized_value and description. A leading wildcard cannot use a B-tree index,
so every search sequentially scanned the whole indicators table -- twice, because
the endpoint also runs a separate count -- and that table grows continuously
under automated feed collection, which the operator does not control
(WILDBO-PERF-02).

pg_trgm GIN indexes make ILIKE '%...%' indexable. The extension is created here;
it ships with PostgreSQL as a standard contrib module.
"""

from alembic import op

revision = "0004_trgm"
down_revision = "0003_vocab"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_indicators_value_trgm "
        "ON indicators USING gin (value gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_indicators_normalized_value_trgm "
        "ON indicators USING gin (normalized_value gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_indicators_description_trgm "
        "ON indicators USING gin (description gin_trgm_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_indicators_description_trgm")
    op.execute("DROP INDEX IF EXISTS idx_indicators_normalized_value_trgm")
    op.execute("DROP INDEX IF EXISTS idx_indicators_value_trgm")
