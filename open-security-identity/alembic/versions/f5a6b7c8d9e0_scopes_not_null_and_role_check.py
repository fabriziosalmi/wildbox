"""Make 'unrestricted' an explicit value, and constrain the membership role.

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-09-08

Two model defects (WILDBO-DOM-07, WILDBO-DOM-09):

1. api_keys.scopes was nullable, with NULL meaning "unrestricted". The most
   privileged state was therefore what an uninitialised column produced, and any
   write path that omitted the field yielded a key the gateway would not
   restrict. Existing NULL rows are migrated to an explicit ['*'] -- the same
   permission, now written rather than inferred -- and the column becomes NOT
   NULL defaulting to [].

2. team_memberships.role was a free String(50) whose legal values existed only
   in a Python enum. A CHECK constraint puts the vocabulary in the database.

Rows with a role outside the vocabulary will make step 2 fail, which is correct:
they are memberships the application cannot interpret. Find them with:

    SELECT DISTINCT role FROM team_memberships
     WHERE role NOT IN ('owner','admin','member');
"""

import sqlalchemy as sa
from alembic import op

revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Legacy NULL scopes -> explicit wildcard, then NOT NULL with a [] default.
    op.execute("UPDATE api_keys SET scopes = '[\"*\"]'::json WHERE scopes IS NULL")
    op.alter_column(
        "api_keys",
        "scopes",
        existing_type=sa.JSON(),
        nullable=False,
        server_default=sa.text("'[]'::json"),
    )

    # 2. Constrain the membership role vocabulary.
    op.create_check_constraint(
        "ck_team_membership_role",
        "team_memberships",
        "role IN ('owner','admin','member')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_team_membership_role", "team_memberships", type_="check")
    op.alter_column(
        "api_keys",
        "scopes",
        existing_type=sa.JSON(),
        nullable=True,
        server_default=None,
    )
