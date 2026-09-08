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
from alembic import op
from app.models import Base

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create every table declared by the models, skipping any that already
    # exist. Two callers, two behaviours, both correct:
    #
    #   * fresh database -- `alembic upgrade head` builds the whole schema here,
    #     so a new deployment needs nothing but alembic. This used to be an
    #     empty upgrade(), which meant `alembic upgrade head` on an empty
    #     database died in 0002 with NoSuchTableError: sources.
    #   * existing database stamped at this revision -- checkfirst makes it a
    #     no-op and 0002 onwards apply the real deltas.
    #
    # The consequence is that this baseline tracks the current models rather
    # than a frozen historical snapshot, so 0002 and 0003 must be idempotent:
    # on a fresh database they find their changes already in place. They are.
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    pass
