"""add scopes column to api_keys (scoped API keys)

Adds a nullable JSON `scopes` column to `api_keys`. NULL means a legacy key
created before scoping existed and is treated as unrestricted (back-compat);
a JSON list of scope strings is enforced at the gateway (path/method -> required
scope). This makes the dashboard's per-key scope selector actually take effect.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-06-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e4f5a6b7c8d9'
down_revision: Union[str, None] = 'd3e4f5a6b7c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('api_keys', sa.Column('scopes', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('api_keys', 'scopes')
