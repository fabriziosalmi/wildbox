"""Add users.tokens_valid_after: a password change ends the other sessions.

Revision ID: a6b7c8d9e0f1
Revises: f5a6b7c8d9e0
Create Date: 2026-10-03

A password change left every token already issued valid until it expired,
so changing the password after a compromise did not lock the intruder out
(#569). Identity does not keep the jtis it issues, so the cutoff is per
user: session tokens issued at or before tokens_valid_after are refused, by
identity's own routes and by /internal/authorize for the gateway.

Nullable, with no backfill: NULL refuses nothing, so the sessions open when
the upgrade runs stay valid until their own expiry, as before.
"""

import sqlalchemy as sa
from alembic import op

revision = "a6b7c8d9e0f1"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("tokens_valid_after", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "tokens_valid_after")
