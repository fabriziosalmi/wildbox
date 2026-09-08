"""Constrain indicator_type and confidence to their declared vocabularies.

Revision ID: 0003_vocab
Revises: 0002_team_id
Create Date: 2026-09-08

IndicatorType and ConfidenceLevel were declared as Python enums and used only to
compute a column default, so the columns themselves accepted any string
(WILDBO-DOM-08). These CHECK constraints put the vocabulary where no writer can
bypass it.

Rows that already violate the vocabulary would make this migration fail, which is
the correct outcome: they are data the application cannot interpret. Inspect them
with:

    SELECT DISTINCT indicator_type FROM indicators
     WHERE indicator_type NOT IN ('ip_address','domain','url','file_hash',
                                  'email','certificate','asn','vulnerability');
"""

from alembic import op

revision = "0003_vocab"
down_revision = "0002_team_id"
branch_labels = None
depends_on = None

_TYPES = "'ip_address','domain','url','file_hash','email','certificate','asn','vulnerability'"
_CONFIDENCE = "'low','medium','high','verified'"


def upgrade() -> None:
    op.create_check_constraint(
        "ck_indicator_type_vocabulary", "indicators", f"indicator_type IN ({_TYPES})"
    )
    op.create_check_constraint(
        "ck_indicator_confidence_vocabulary",
        "indicators",
        f"confidence IN ({_CONFIDENCE})",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_indicator_confidence_vocabulary", "indicators", type_="check"
    )
    op.drop_constraint("ck_indicator_type_vocabulary", "indicators", type_="check")
