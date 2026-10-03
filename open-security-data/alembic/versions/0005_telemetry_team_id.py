"""Give telemetry an owning team.

Revision ID: 0005_telemetry_team
Revises: 0004_trgm
Create Date: 2026-10-03

Telemetry events and sensor records had no team: any authenticated caller
listed every team's events, and a sensor ID was unique across all teams, so a
sensor of one team reporting under the same ID as another's updated the other
team's record (#628). Both tables gain team_id, the team of the API key the
sensor authenticated with at the gateway, and a sensor ID becomes unique per
team.

Until #628 no batch could be ingested (the sensor's credential was refused),
so existing rows can only have been written by hand. They keep team_id NULL,
which the API shows to no team.

Idempotent, like 0002 and 0003: on a fresh database the 0001 baseline has
already created the tables from the current models.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_telemetry_team"
down_revision = "0004_trgm"
branch_labels = None
depends_on = None

SENSOR_ID_INDEX = "ix_sensor_metadata_sensor_id"
UNIQUE_PER_TEAM = "uq_sensor_metadata_team_sensor"


def _inspector():
    return sa.inspect(op.get_bind())


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in _inspector().get_columns(table)}


def _indexes(table: str) -> dict:
    return {ix["name"]: ix for ix in _inspector().get_indexes(table)}


def _unique_constraints(table: str) -> set:
    return {uc["name"] for uc in _inspector().get_unique_constraints(table)}


def _add_team_id(table: str) -> None:
    if not _has_column(table, "team_id"):
        op.add_column(
            table,
            sa.Column("team_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
    if f"ix_{table}_team_id" not in _indexes(table):
        op.create_index(f"ix_{table}_team_id", table, ["team_id"])


def upgrade() -> None:
    _add_team_id("telemetry_events")
    _add_team_id("sensor_metadata")

    if "idx_telemetry_team_timestamp" not in _indexes("telemetry_events"):
        op.create_index(
            "idx_telemetry_team_timestamp",
            "telemetry_events",
            ["team_id", "timestamp"],
        )

    # sensor_id was declared unique=True, index=True, which create_all()
    # builds as a unique index. Replace it with a plain one plus uniqueness
    # per team.
    existing = _indexes("sensor_metadata").get(SENSOR_ID_INDEX)
    if existing is not None and existing.get("unique"):
        op.drop_index(SENSOR_ID_INDEX, table_name="sensor_metadata")
        existing = None
    if existing is None:
        op.create_index(SENSOR_ID_INDEX, "sensor_metadata", ["sensor_id"])
    if UNIQUE_PER_TEAM not in _unique_constraints("sensor_metadata"):
        op.create_unique_constraint(
            UNIQUE_PER_TEAM, "sensor_metadata", ["team_id", "sensor_id"]
        )


def downgrade() -> None:
    # Restoring global uniqueness fails if two teams now share a sensor ID;
    # that is the data this revision exists to allow, so it is left to the
    # operator rather than deleted here.
    if UNIQUE_PER_TEAM in _unique_constraints("sensor_metadata"):
        op.drop_constraint(UNIQUE_PER_TEAM, "sensor_metadata", type_="unique")
    if SENSOR_ID_INDEX in _indexes("sensor_metadata"):
        op.drop_index(SENSOR_ID_INDEX, table_name="sensor_metadata")
    op.create_index(SENSOR_ID_INDEX, "sensor_metadata", ["sensor_id"], unique=True)
    if "idx_telemetry_team_timestamp" in _indexes("telemetry_events"):
        op.drop_index("idx_telemetry_team_timestamp", table_name="telemetry_events")
    for table in ("sensor_metadata", "telemetry_events"):
        if f"ix_{table}_team_id" in _indexes(table):
            op.drop_index(f"ix_{table}_team_id", table_name=table)
        if _has_column(table, "team_id"):
            op.drop_column(table, "team_id")
