"""Telemetry belongs to the team whose sensor reported it (#628).

A sensor ingests through the gateway with an identity API key, and the gateway
forwards the key's team. The data service stores every event and the sensor's
record under that team, whatever the batch claims, and serves each team only
its own: the events, the sensors, a sensor by ID and the statistics. Before
this, telemetry had no team at all, and a sensor ID was unique across teams,
so one team's sensor updated another's record.

The endpoints run against an in-memory SQLite database.
"""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api import main  # noqa: E402
from app.auth import GatewayUser  # noqa: E402
from app.models import SensorMetadata, TelemetryEvent  # noqa: E402


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


TEAM_A = uuid.uuid4()
TEAM_B = uuid.uuid4()
NOW = datetime.now(timezone.utc).isoformat()


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [TelemetryEvent.__table__, SensorMetadata.__table__]
    TelemetryEvent.metadata.create_all(engine, tables=tables)
    # autoflush=False, as app/utils/database.py builds the service's sessions:
    # with the default, a record added earlier in the batch is flushed by the
    # next query and found, which hid the duplicate-sensor bug in ingest.
    session = sessionmaker(bind=engine, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    main.app.dependency_overrides.clear()


def as_team(db, team_id):
    user = GatewayUser(user_id=uuid.uuid4(), team_id=team_id, role="member")
    main.app.dependency_overrides[main.get_current_user] = lambda: user
    # The ingest route has a dependency of its own, with its scope (#637).
    main.app.dependency_overrides[main.get_ingest_user] = lambda: user
    main.app.dependency_overrides[main.get_db] = lambda: db
    return TestClient(main.app)


def batch(sensor_id, count=2, **extra):
    """A batch as the sensor's forwarder builds it."""
    return {
        "batch_id": str(uuid.uuid4()),
        "events": [
            {
                "sensor_id": sensor_id,
                "event_type": "network_connection",
                "timestamp": NOW,
                "source_host": "web-1",
                "event_data": {"type": "network.listening_ports", "n": i},
                "tags": ["network.listening_ports"],
                **extra,
            }
            for i in range(count)
        ],
    }


def ingest(db, team_id, body):
    response = as_team(db, team_id).post("/api/v1/ingest", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def events(db, team_id, **params):
    response = as_team(db, team_id).get("/api/v1/telemetry/events", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_events_are_stored_under_the_callers_team(db):
    result = ingest(db, TEAM_A, batch("sensor-1"))

    assert result["events_ingested"] == 2
    rows = db.query(TelemetryEvent).all()
    assert {row.team_id for row in rows} == {TEAM_A}
    (sensor,) = db.query(SensorMetadata).all()
    assert sensor.team_id == TEAM_A
    assert sensor.total_events == 2


def test_a_batch_from_a_new_sensor_creates_one_record(db):
    ingest(db, TEAM_A, batch("new-sensor", count=5))
    ingest(db, TEAM_A, batch("new-sensor", count=3))

    (sensor,) = db.query(SensorMetadata).all()
    assert sensor.total_events == 8


def test_a_team_lists_its_events_and_no_other_teams(db):
    ingest(db, TEAM_A, batch("sensor-1"))

    assert len(events(db, TEAM_A)) == 2
    assert len(events(db, TEAM_A, sensor_id="sensor-1")) == 2
    assert events(db, TEAM_B) == []
    assert events(db, TEAM_B, sensor_id="sensor-1") == []


def test_a_team_the_batch_names_is_ignored(db):
    # A key of team A cannot write for team B: the team is the one the gateway
    # authenticated, not one in the body.
    body = batch("sensor-1", team_id=str(TEAM_B))
    body["team_id"] = str(TEAM_B)

    ingest(db, TEAM_A, body)

    assert events(db, TEAM_B) == []
    assert {row.team_id for row in db.query(TelemetryEvent).all()} == {TEAM_A}


def test_the_same_sensor_id_in_two_teams_is_two_sensors(db):
    ingest(db, TEAM_A, batch("shared-name", count=2))
    ingest(db, TEAM_B, batch("shared-name", count=3))

    records = {row.team_id: row for row in db.query(SensorMetadata).all()}
    assert set(records) == {TEAM_A, TEAM_B}
    assert records[TEAM_A].total_events == 2
    assert records[TEAM_B].total_events == 3
    assert len(events(db, TEAM_A)) == 2
    assert len(events(db, TEAM_B)) == 3


def test_sensors_are_listed_and_found_per_team(db):
    ingest(db, TEAM_A, batch("sensor-a"))
    ingest(db, TEAM_B, batch("sensor-b"))

    listed = as_team(db, TEAM_A).get("/api/v1/sensors").json()
    assert [s["sensor_id"] for s in listed] == ["sensor-a"]

    assert as_team(db, TEAM_A).get("/api/v1/sensors/sensor-a").status_code == 200
    assert as_team(db, TEAM_A).get("/api/v1/sensors/sensor-b").status_code == 404


def test_statistics_count_the_callers_team_only(db):
    ingest(db, TEAM_A, batch("sensor-a", count=2))
    ingest(db, TEAM_B, batch("sensor-b", count=5))

    stats = as_team(db, TEAM_A).get("/api/v1/telemetry/stats").json()

    assert stats["total_events"] == 2
    assert stats["active_sensors"] == 1
    assert stats["events_by_type"] == {"network_connection": 2}


def test_rows_without_a_team_are_shown_to_no_team(db):
    db.add(
        TelemetryEvent(
            team_id=None,
            sensor_id="legacy",
            event_type="security_event",
            timestamp=datetime.now(timezone.utc),
            event_data={},
            tags=[],
        )
    )
    db.commit()

    assert events(db, TEAM_A) == []
    assert events(db, TEAM_B) == []
