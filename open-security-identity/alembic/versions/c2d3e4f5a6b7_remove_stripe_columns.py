"""remove stripe billing columns

Removes the Stripe integration: drops users.stripe_customer_id and
subscriptions.stripe_subscription_id (and their unique indexes). The
Subscription/plan-tier model itself is kept (free tier; used by the gateway
for permissions and rate limits) — only the Stripe coupling is removed.

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5g6
Create Date: 2026-06-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c2d3e4f5a6b7'
down_revision: Union[str, None] = 'b1c2d3e4f5g6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres drops the associated unique index automatically with the column.
    op.drop_column('users', 'stripe_customer_id')
    op.drop_column('subscriptions', 'stripe_subscription_id')


def downgrade() -> None:
    op.add_column(
        'subscriptions',
        sa.Column('stripe_subscription_id', sa.String(length=255), nullable=True),
    )
    op.create_index(
        op.f('ix_subscriptions_stripe_subscription_id'),
        'subscriptions',
        ['stripe_subscription_id'],
        unique=True,
    )
    op.add_column(
        'users',
        sa.Column('stripe_customer_id', sa.String(length=255), nullable=True),
    )
    op.create_index(
        op.f('ix_users_stripe_customer_id'),
        'users',
        ['stripe_customer_id'],
        unique=True,
    )
