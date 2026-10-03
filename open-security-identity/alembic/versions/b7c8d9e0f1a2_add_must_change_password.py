"""Add users.must_change_password: accounts created by a team admin.

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1
Create Date: 2026-10-03

A team owner or admin can now create an account directly in their team,
with an initial password they choose (#573). The administrator must not
keep knowing it, so the account is flagged until its user changes the
password: identity and the gateway refuse every other request of a
flagged account's session.

NOT NULL with a server default of false, so every existing account is
unflagged by the upgrade and nothing changes for it.
"""

import sqlalchemy as sa
from alembic import op

revision = "b7c8d9e0f1a2"
down_revision = "a6b7c8d9e0f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
