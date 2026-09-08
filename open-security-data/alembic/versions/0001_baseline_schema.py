"""Baseline: the schema as created by Base.metadata.create_all().

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-08

This revision is a no-op against a database that already exists: it stamps the
current shape so that later revisions have a known starting point. A fresh
database is created from the models by the application's create_tables() call
and then stamped, or created by running `alembic upgrade head` after this
revision has been fleshed out with the full DDL.

The data service previously had no migration mechanism at all -- alembic was a
declared dependency and was never wired up (WILDBO-DOM-02).
"""

# Kept even though this revision's upgrade() is empty: every alembic revision
# file is expected to carry these two, and the next hand-written revision starts
# from a copy of this one.
import sqlalchemy as sa  # noqa: F401
from alembic import op  # noqa: F401

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Intentionally empty. The baseline exists so that 0002 and later have a
    # parent; existing deployments are stamped with `alembic stamp 0001_baseline`
    # and new ones reach this state via create_tables().
    pass


def downgrade() -> None:
    pass
