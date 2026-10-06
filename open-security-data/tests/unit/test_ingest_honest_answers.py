"""POST /api/v1/ingest stores a batch whole or not at all, and says which (#755).

The route answered 200 with ``events_ingested: 0`` when the commit failed with
an error that was not SQLAlchemy's. A client that reads the status took the
batch for stored. On PostgreSQL a NUL character in ``source_host`` or
``raw_data`` did exactly that (psycopg2 refuses the string with a
``ValueError``), and took the other events of its batch with it. An event the
loop could not process was counted out and the rest kept, after the sensor's
record had already counted it. And a value the schema let through and a
column could not hold (a ``sensor_id`` of 300 characters) was a 503 "send it
again", which a sensor obeys for ever.

Now: one transaction for the batch. ``events_ingested`` is what was stored,
which is all of it or, with an error status and the canonical error body,
none of it. What the answer is for each kind of failure is written down in
``tests/shared/ingest_answer_vectors.json``, which the sensor's tests read
too: the sensor splits a batch on a 422 and keeps it on a 5xx.

The endpoints run against an in-memory SQLite database.
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import DataError, IntegrityError, OperationalError
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api import main  # noqa: E402
from app.auth import GatewayUser  # noqa: E402
from app.models import SensorMetadata, TelemetryEvent  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = {
    answer["case"]: answer
    for answer in json.loads(
        (REPO_ROOT / "tests" / "shared" / "ingest_answer_vectors.json").read_text()
    )["answers"]
}


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


TEAM = uuid.uuid4()
NOW = datetime.now(timezone.utc).isoformat()
MARK = "value-755-" + uuid.uuid4().hex


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


@pytest.fixture
def client(db):
    user = GatewayUser(user_id=uuid.uuid4(), team_id=TEAM, role="member")
    main.app.dependency_overrides[main.get_current_user] = lambda: user
    main.app.dependency_overrides[main.get_ingest_user] = lambda: user
    main.app.dependency_overrides[main.get_db] = lambda: db
    yield TestClient(main.app, raise_server_exceptions=False)
    main.app.dependency_overrides.clear()


def event(sensor_id="sensor-1", **changes):
    body = {
        "sensor_id": sensor_id,
        "event_type": "security_event",
        "timestamp": NOW,
        "source_host": "web-1",
        "event_data": {"type": "log.auth"},
        "tags": ["log.auth"],
    }
    body.update(changes)
    return body


def batch(*events):
    return {"batch_id": str(uuid.uuid4()), "events": list(events)}


def stored(db):
    """(events, {sensor_id: total_events}) in the database, read afresh.

    The request must have left nothing pending in its session either: what a
    failed batch added and did not roll back would be stored by the next
    commit on that session.
    """
    assert not db.new and not db.dirty, "the request left work in its session"
    db.expire_all()
    events = db.query(TelemetryEvent).count()
    sensors = {row.sensor_id: row.total_events for row in db.query(SensorMetadata)}
    return events, sensors


def canonical(response, status):
    """The canonical error body, with its request id; return the error."""
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"error"}, body
    error = body["error"]
    assert error["code"] == status
    assert isinstance(error["message"], str) and error["message"]
    assert error["request_id"]
    return error


def raising(error):
    def commit():
        raise error

    return commit


# --- a batch that was stored ------------------------------------------------------


@pytest.mark.parametrize("count", [1, 3, 25])
def test_a_stored_batch_says_how_many_events_it_stored(client, db, count):
    response = client.post("/api/v1/ingest", json=batch(*[event()] * count))

    assert response.status_code == VECTORS["stored"]["status"]
    body = response.json()
    assert set(body) == set(VECTORS["stored"]["body"])
    assert body["events_received"] == count
    assert body["events_ingested"] == count
    assert body["errors"] == []
    assert stored(db) == (count, {"sensor-1": count})


def test_an_empty_batch_stores_nothing_and_says_so(client, db):
    response = client.post("/api/v1/ingest", json=batch())

    assert response.status_code == 200, response.text
    assert response.json()["events_ingested"] == 0
    assert stored(db) == (0, {})


# --- a fault of the service: 5xx, nothing stored ---------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        # What psycopg2 raises for a NUL character in a text column.
        ValueError("A string literal cannot contain NUL (0x00) characters."),
        KeyError(MARK),
        TypeError(f"unsupported operand for {MARK}"),
        ConnectionError(f"connection to db-7.internal lost while storing {MARK}"),
        TimeoutError(),
        RuntimeError(MARK),
    ],
    ids=lambda error: type(error).__name__,
)
def test_a_commit_that_fails_is_an_error_status_and_not_a_200(
    client, db, monkeypatch, caplog, error
):
    """The defect: 200 with events_ingested 0 for five of these six."""
    monkeypatch.setattr(db, "commit", raising(error))

    with caplog.at_level("ERROR"):
        response = client.post("/api/v1/ingest", json=batch(event(), event(), event()))

    vector = VECTORS["service_fault"]
    answered = canonical(response, vector["status"])
    assert answered["message"] == vector["body"]["error"]["message"]
    assert answered["type"] == vector["body"]["error"]["type"]
    assert "events_ingested" not in response.text
    assert stored(db) == (0, {})
    # Neither the answer nor the log repeats what the error said.
    assert MARK not in response.text
    assert MARK not in caplog.text
    assert f"{type(error).__name__}" in caplog.text


def test_the_clients_own_batch_id_is_answered_and_not_logged(
    client, db, monkeypatch, caplog
):
    """batch_id is whatever the client wrote; every log line used to name it."""
    body = dict(batch(event(), event()), batch_id=MARK)

    with caplog.at_level("DEBUG"):
        stored_answer = client.post("/api/v1/ingest", json=body)
        monkeypatch.setattr(db, "commit", raising(ValueError("no")))
        failed = client.post("/api/v1/ingest", json=body)

    assert stored_answer.status_code == 200, stored_answer.text
    assert stored_answer.json()["batch_id"] == MARK
    assert failed.status_code == 500
    assert MARK not in caplog.text
    assert f"Ingested a batch of 2 events of team {TEAM}" in caplog.text
    assert f"Failed to store a batch of 2 events of team {TEAM}: ValueError" in (
        caplog.text
    )


def test_an_event_that_cannot_be_processed_fails_the_batch_whole(
    client, db, monkeypatch
):
    """It was counted out and the rest kept, after its sensor had counted it."""
    real, made = main.TelemetryEventRow, []

    def second_one_fails(**columns):
        made.append(columns)
        if len(made) == 2:
            raise TypeError(f"cannot build a row from {MARK}")
        return real(**columns)

    monkeypatch.setattr(main, "TelemetryEventRow", second_one_fails)

    response = client.post("/api/v1/ingest", json=batch(event(), event(), event()))

    canonical(response, 500)
    assert MARK not in response.text
    # No event, and no sensor record that counts events nobody stored.
    assert stored(db) == (0, {})

    # The same sensor's next batch counts its own events only.
    monkeypatch.setattr(main, "TelemetryEventRow", real)
    again = client.post("/api/v1/ingest", json=batch(event(), event()))
    assert again.status_code == 200, again.text
    assert again.json()["events_ingested"] == 2
    assert stored(db) == (2, {"sensor-1": 2})


def test_a_failed_batch_leaves_an_existing_sensors_count_alone(client, db, monkeypatch):
    assert client.post("/api/v1/ingest", json=batch(event())).status_code == 200
    assert stored(db) == (1, {"sensor-1": 1})

    monkeypatch.setattr(db, "commit", raising(ValueError("no")))
    response = client.post("/api/v1/ingest", json=batch(event(), event()))

    canonical(response, 500)
    assert stored(db) == (1, {"sensor-1": 1})


# --- the database did not take it, for a reason that may pass: 503 ------------------------


@pytest.mark.parametrize(
    "error",
    [
        OperationalError("INSERT", {}, Exception("server closed the connection")),
        IntegrityError("INSERT", {}, Exception("duplicate key")),
    ],
    ids=lambda error: type(error).__name__,
)
def test_a_database_that_does_not_take_the_batch_asks_for_it_again(
    client, db, monkeypatch, error
):
    monkeypatch.setattr(db, "commit", raising(error))

    response = client.post("/api/v1/ingest", json=batch(event(), event()))

    vector = VECTORS["database_unavailable"]
    answered = canonical(response, vector["status"])
    assert answered["message"] == vector["body"]["error"]["message"]
    assert response.headers["Retry-After"] == vector["headers"]["Retry-After"]
    assert stored(db) == (0, {})


# --- the payload: 422, nothing stored, the event named ---------------------------------


def test_a_value_the_database_refuses_is_about_the_payload(client, db, monkeypatch):
    """A 503 "send it again" used to answer this: the same answer, for ever."""
    refused = DataError("INSERT", {}, Exception("value too long for type varchar"))
    monkeypatch.setattr(db, "commit", raising(refused))

    response = client.post("/api/v1/ingest", json=batch(event(), event()))

    vector = VECTORS["value_not_storable"]
    answered = canonical(response, vector["status"])
    assert answered["message"] == vector["body"]["error"]["message"]
    assert answered["details"] == vector["body"]["error"]["details"]
    assert "Retry-After" not in response.headers
    assert stored(db) == (0, {})


INVALID = {
    "sensor_id too long": ({"sensor_id": "s" * 256}, "sensor_id", "string_too_long"),
    "source_host too long": (
        {"source_host": "h" * 256},
        "source_host",
        "string_too_long",
    ),
    "NUL in sensor_id": ({"sensor_id": f"{MARK}\x00"}, "sensor_id", "value_error"),
    "NUL in source_host": (
        {"source_host": f"{MARK}\x00"},
        "source_host",
        "value_error",
    ),
    "NUL in raw_data": ({"raw_data": f"{MARK}\x00"}, "raw_data", "value_error"),
    "unknown event_type": ({"event_type": MARK}, "event_type", "enum"),
    "no timestamp": ({"timestamp": None}, "timestamp", "datetime_type"),
    "severity out of range": ({"severity": 11}, "severity", "less_than_equal"),
}


@pytest.mark.parametrize("name", INVALID)
def test_one_invalid_event_refuses_its_batch_and_is_named_by_its_place(
    client, db, name
):
    """What the database would refuse about an event, the schema refuses first.

    Each of the first five cases passed the schema: a column of 255
    characters, or one that cannot hold a NUL, refused it afterwards.
    """
    changes, field, kind = INVALID[name]
    events = [event(), event(), event(**changes), event()]

    response = client.post("/api/v1/ingest", json=batch(*events))

    vector = VECTORS["invalid_event"]
    answered = canonical(response, vector["status"])
    assert answered["type"] == vector["body"]["error"]["type"]
    assert answered["message"] == vector["body"]["error"]["message"]
    # The third event, by its index, and the field: enough for a client to
    # find it, and for a sensor to know the batch is at fault.
    assert [(item["loc"], item["type"]) for item in answered["details"]] == [
        (["body", "events", 2, field], kind)
    ]
    assert set(answered["details"][0]) == set(vector["body"]["error"]["details"][0])
    assert MARK not in response.text
    # None of the four was stored: not the three valid ones either.
    assert stored(db) == (0, {})


def test_the_valid_events_of_a_refused_batch_are_stored_when_sent_without_it(
    client, db
):
    """What the sensor does on a 422: halve the batch until the event is alone."""
    events = [event(), event(sensor_id="s" * 300), event(), event()]

    def deliver(part):
        if client.post("/api/v1/ingest", json=batch(*part)).status_code == 200:
            return len(part), 0
        if len(part) == 1:
            return 0, 1
        half = len(part) // 2
        left, right = deliver(part[:half]), deliver(part[half:])
        return left[0] + right[0], left[1] + right[1]

    assert deliver(events) == (3, 1)
    assert stored(db) == (3, {"sensor-1": 3})


def test_what_the_schema_allows_is_what_the_columns_hold():
    """The lengths the schema checks are the columns' own."""
    from app.schemas.api import TelemetryEventCreate

    fields = TelemetryEventCreate.model_fields
    for name in ("sensor_id", "source_host"):
        column = TelemetryEvent.__table__.c[name]
        lengths = [
            m.max_length for m in fields[name].metadata if hasattr(m, "max_length")
        ]
        assert lengths == [column.type.length], name
    assert SensorMetadata.__table__.c["sensor_id"].type.length == 255
    assert SensorMetadata.__table__.c["hostname"].type.length == 255


def test_the_longest_values_the_schema_allows_are_stored(client, db):
    longest = event(sensor_id="s" * 255, source_host="h" * 255, raw_data="r" * 5000)

    response = client.post("/api/v1/ingest", json=batch(longest))

    assert response.status_code == 200, response.text
    assert stored(db) == (1, {"s" * 255: 1})


def test_too_many_events_is_refused_before_anything_is_stored(client, db, monkeypatch):
    vector = VECTORS["too_many_events"]
    monkeypatch.setattr(main.config.security, "max_batch_size", 2)

    response = client.post("/api/v1/ingest", json=batch(event(), event(), event()))

    answered = canonical(response, vector["status"])
    assert answered["message"] == vector["body"]["error"]["message"]
    assert stored(db) == (0, {})


# --- the vectors themselves ------------------------------------------------------------


def test_every_answer_the_sensor_is_told_about_is_produced_above():
    assert set(VECTORS) == {
        "stored",
        "invalid_event",
        "value_not_storable",
        "too_many_events",
        "database_unavailable",
        "service_fault",
    }
    for case, vector in VECTORS.items():
        if vector["status"] == 200:
            assert vector["body"]["events_ingested"] == vector["events"], case
        else:
            # The shape the services answer errors in: the sensor tells a
            # refusal of the data service from one of nginx by it.
            assert isinstance(vector["body"]["error"], dict), case
            assert vector["body"]["error"]["code"] == vector["status"], case
