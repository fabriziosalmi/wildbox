"""Team B can neither read nor overwrite team A's telemetry (#641).

The acceptance scenario of #641, run against the endpoints on an in-memory
SQLite database: team A ingests a batch for sensor ``s1``; team B then

1. lists events, sensors and statistics and sees none of A's data,
2. gets 404 for ``/api/v1/sensors/s1``,
3. ingests a batch with ``sensor_id=s1``, and A's ``s1`` record is unchanged.

Each read is checked both unfiltered and filtered by ``sensor_id``, because
each code path builds its own query, and every assertion names the endpoint
it covers. Dropping the team predicate from any one of the reads, or from the
ingest's sensor lookup, fails at least one test here. Rows written before
telemetry had a team (``team_id`` NULL) are visible to no team, and an ingest
never adopts them.
"""

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import IntegrityError
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
SENSOR = "s1"


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [TelemetryEvent.__table__, SensorMetadata.__table__]
    TelemetryEvent.metadata.create_all(engine, tables=tables)
    # autoflush=False, as app/utils/database.py builds the service's sessions.
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


def client(db, team_id):
    user = GatewayUser(user_id=uuid.uuid4(), team_id=team_id, role="member")
    main.app.dependency_overrides[main.get_current_user] = lambda: user
    main.app.dependency_overrides[main.get_db] = lambda: db
    return TestClient(main.app)


def batch(sensor_id, count, host, event_type="process_event", **extra):
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "events": [
            {
                "sensor_id": sensor_id,
                "event_type": event_type,
                "timestamp": timestamp,
                "source_host": host,
                "event_data": {"pid": 1000 + i, "host": host},
                "raw_data": f"secret raw line from {host}",
                **extra,
            }
            for i in range(count)
        ],
    }


def ingest(db, team_id, body):
    response = client(db, team_id).post("/api/v1/ingest", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["errors"] == []
    return response.json()


def get(db, team_id, path, **params):
    response = client(db, team_id).get(path, params=params)
    assert response.status_code == 200, f"{path}: {response.text}"
    return response.json()


def sensor_row(db, team_id, sensor_id=SENSOR):
    db.expire_all()
    return (
        db.query(SensorMetadata)
        .filter(
            SensorMetadata.team_id == team_id, SensorMetadata.sensor_id == sensor_id
        )
        .one()
    )


@pytest.fixture
def team_a_ingested(db):
    """Team A's sensor s1 has reported three events."""
    ingest(db, TEAM_A, batch(SENSOR, 3, "a-host"))
    return db


# (1) Team B lists events, sensors and statistics and sees none of A's data.


@pytest.mark.parametrize("params", [{}, {"sensor_id": SENSOR}])
def test_events_of_team_a_are_not_listed_for_team_b(team_a_ingested, params):
    db = team_a_ingested
    assert len(get(db, TEAM_A, "/api/v1/telemetry/events", **params)) == 3
    assert get(db, TEAM_B, "/api/v1/telemetry/events", **params) == []


@pytest.mark.parametrize("active_only", ["true", "false"])
def test_sensors_of_team_a_are_not_listed_for_team_b(team_a_ingested, active_only):
    db = team_a_ingested
    listed = get(db, TEAM_A, "/api/v1/sensors", active_only=active_only)
    assert [s["sensor_id"] for s in listed] == [SENSOR]
    assert get(db, TEAM_B, "/api/v1/sensors", active_only=active_only) == []


@pytest.mark.parametrize("params", [{}, {"sensor_id": SENSOR}])
def test_statistics_of_team_b_do_not_count_team_a(team_a_ingested, params):
    db = team_a_ingested
    a = get(db, TEAM_A, "/api/v1/telemetry/stats", **params)
    assert a["total_events"] == 3
    assert a["events_by_type"] == {"process_event": 3}
    assert a["active_sensors"] == 1

    b = get(db, TEAM_B, "/api/v1/telemetry/stats", **params)
    assert b["total_events"] == 0, "stats: total_events counts another team"
    assert b["events_by_type"] == {}, "stats: events_by_type counts another team"
    assert b["active_sensors"] == 0, "stats: active_sensors counts another team"


# (2) Team B gets 404 for A's sensor.


def test_team_b_gets_404_for_team_a_sensor(team_a_ingested):
    db = team_a_ingested
    assert client(db, TEAM_A).get(f"/api/v1/sensors/{SENSOR}").status_code == 200
    response = client(db, TEAM_B).get(f"/api/v1/sensors/{SENSOR}")
    assert response.status_code == 404, response.text


# (3) Team B ingesting under A's sensor ID leaves A's record unchanged.


def test_team_b_ingesting_the_same_sensor_id_does_not_touch_team_a(team_a_ingested):
    db = team_a_ingested
    before = sensor_row(db, TEAM_A)
    snapshot = {
        "id": before.id,
        "total_events": before.total_events,
        "last_seen": before.last_seen,
        "last_event_at": before.last_event_at,
        "first_seen": before.first_seen,
        "hostname": before.hostname,
        "active": before.active,
    }

    ingest(db, TEAM_B, batch(SENSOR, 2, "b-host"))

    after = sensor_row(db, TEAM_A)
    assert {key: getattr(after, key) for key in snapshot} == snapshot

    b_record = sensor_row(db, TEAM_B)
    assert b_record.id != snapshot["id"]
    assert b_record.total_events == 2
    assert b_record.hostname == "b-host"

    # Each team reads its own s1 and only its own events.
    a_sensor = get(db, TEAM_A, f"/api/v1/sensors/{SENSOR}")
    b_sensor = get(db, TEAM_B, f"/api/v1/sensors/{SENSOR}")
    assert (a_sensor["total_events"], a_sensor["hostname"]) == (3, "a-host")
    assert (b_sensor["total_events"], b_sensor["hostname"]) == (2, "b-host")
    a_events = get(db, TEAM_A, "/api/v1/telemetry/events", sensor_id=SENSOR)
    b_events = get(db, TEAM_B, "/api/v1/telemetry/events", sensor_id=SENSOR)
    assert {e["source_host"] for e in a_events} == {"a-host"}
    assert {e["source_host"] for e in b_events} == {"b-host"}
    assert get(db, TEAM_A, "/api/v1/telemetry/stats")["total_events"] == 3
    assert get(db, TEAM_B, "/api/v1/telemetry/stats")["total_events"] == 2


def test_a_team_named_in_the_batch_is_ignored(db):
    # Team B tries to write into team A's s1, naming A in the batch and in
    # every event. The data service stores under the authenticated caller.
    body = batch(SENSOR, 1, "b-host", team_id=str(TEAM_A))
    body["team_id"] = str(TEAM_A)

    ingest(db, TEAM_B, body)

    db.expire_all()
    assert {row.team_id for row in db.query(TelemetryEvent).all()} == {TEAM_B}
    assert {row.team_id for row in db.query(SensorMetadata).all()} == {TEAM_B}
    assert get(db, TEAM_A, "/api/v1/telemetry/events") == []
    assert get(db, TEAM_A, "/api/v1/sensors") == []


# The schema enforces a sensor ID per team, not globally.


def test_sensor_id_is_unique_per_team_in_the_schema(db):
    now = datetime.now(timezone.utc)
    db.add(SensorMetadata(team_id=TEAM_A, sensor_id=SENSOR, last_seen=now))
    db.add(SensorMetadata(team_id=TEAM_B, sensor_id=SENSOR, last_seen=now))
    db.commit()

    db.add(SensorMetadata(team_id=TEAM_A, sensor_id=SENSOR, last_seen=now))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# Legacy rows (team_id NULL, written before telemetry had a team).


@pytest.fixture
def legacy(db):
    seen = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.add(
        SensorMetadata(
            team_id=None,
            sensor_id=SENSOR,
            hostname="legacy-host",
            first_seen=seen,
            last_seen=seen,
            active=True,
            total_events=7,
        )
    )
    db.add(
        TelemetryEvent(
            team_id=None,
            sensor_id=SENSOR,
            event_type="security_event",
            timestamp=seen,
            source_host="legacy-host",
            event_data={},
            tags=[],
        )
    )
    db.commit()
    return db


@pytest.mark.parametrize("team_id", [TEAM_A, TEAM_B])
def test_legacy_rows_are_visible_to_no_team(legacy, team_id):
    db = legacy
    assert get(db, team_id, "/api/v1/telemetry/events") == []
    assert get(db, team_id, "/api/v1/sensors", active_only="false") == []
    assert client(db, team_id).get(f"/api/v1/sensors/{SENSOR}").status_code == 404
    stats = get(db, team_id, "/api/v1/telemetry/stats")
    assert (stats["total_events"], stats["active_sensors"]) == (0, 0)
    assert stats["events_by_type"] == {}


def test_an_ingest_does_not_adopt_a_legacy_sensor_record(legacy):
    db = legacy

    ingest(db, TEAM_A, batch(SENSOR, 1, "a-host"))

    db.expire_all()
    orphan = (
        db.query(SensorMetadata)
        .filter(SensorMetadata.team_id.is_(None), SensorMetadata.sensor_id == SENSOR)
        .one()
    )
    assert (orphan.total_events, orphan.hostname) == (7, "legacy-host")
    assert sensor_row(db, TEAM_A).total_events == 1
