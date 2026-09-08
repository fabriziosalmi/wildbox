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

import sqlalchemy as sa
from alembic import op

revision = "0003_vocab"
down_revision = "0002_team_id"
branch_labels = None
depends_on = None

_TYPES = "'ip_address','domain','url','file_hash','email','certificate','asn','vulnerability'"
_CONFIDENCE = "'low','medium','high','verified'"


def _has_constraint(name: str) -> bool:
    """True if the named constraint is already on the indicators table.

    Needed because 0001 now builds a fresh schema from the models, which
    already carry these two checks: without the guard, `alembic upgrade head`
    on an empty database fails here with "constraint already exists".
    """
    bind = op.get_bind()
    return bool(
        bind.execute(
            sa.text(
                "SELECT 1 FROM pg_constraint c "
                "JOIN pg_class t ON t.oid = c.conrelid "
                "WHERE t.relname = 'indicators' AND c.conname = :name"
            ),
            {"name": name},
        ).scalar()
    )


def _reject_rows_outside(column: str, vocabulary: str) -> None:
    """Refuse to run rather than let PostgreSQL raise a bare CheckViolation.

    Adding the constraint to a table that already holds values outside the
    vocabulary fails with "check constraint ... is violated by some row" and
    nothing else -- no column, no offending values, no hint about what to do.
    PostgreSQL's transactional DDL means the migration rolls back cleanly, so
    nothing is corrupted, but the operator is left guessing. This lists the
    actual values and the query that fixes them.
    """
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                f"SELECT {column} AS bad, count(*) AS n FROM indicators "  # noqa: S608
                f"WHERE {column} IS NOT NULL AND {column} NOT IN ({vocabulary}) "
                f"GROUP BY {column} ORDER BY n DESC"
            )
        )
        .fetchall()
    )
    if not rows:
        return
    detail = ", ".join(f"{r.bad!r} ({r.n} rows)" for r in rows)
    raise RuntimeError(
        f"indicators.{column} holds values outside the declared vocabulary: "
        f"{detail}. Map them before migrating, e.g.\n"
        f"    UPDATE indicators SET {column} = '<valid value>' "
        f"WHERE {column} = '<bad value>';\n"
        f"Valid values are: {vocabulary}."
    )


def upgrade() -> None:
    _reject_rows_outside("indicator_type", _TYPES)
    _reject_rows_outside("confidence", _CONFIDENCE)
    if not _has_constraint("ck_indicator_type_vocabulary"):
        op.create_check_constraint(
            "ck_indicator_type_vocabulary",
            "indicators",
            f"indicator_type IN ({_TYPES})",
        )
    if not _has_constraint("ck_indicator_confidence_vocabulary"):
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
