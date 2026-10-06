"""A database error is logged without the values PostgreSQL writes in it (#778).

``hide_parameters`` on the engine (#755) removes the bound parameters from
the text of a SQLAlchemy error. The message the server wrote is still in
that text, and PostgreSQL writes values in its messages::

    duplicate key value violates unique constraint "uq_source_indicator"
    DETAIL:  Key (source_id, indicator_type, normalized_value)=(...) already
    exists.

    invalid input syntax for type inet: "what the caller searched for"

Three places wrote that text to the log: the shared handler, for a database
error no route caught; the collector, when an indicator could not be stored;
and the traceback logged for the collection that failed with it.

The first tests make the errors for real: the service's own tables on a
PostgreSQL server, through psycopg2. They need Docker
(throwaway_postgres.py). The others give the service errors of the same
shape and run everywhere.
"""

import asyncio
import logging
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import (
    DataError,
    IntegrityError,
    OperationalError,
    SQLAlchemyError,
)
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.api.main as main  # noqa: E402
import throwaway_postgres  # noqa: E402
from app import collectors  # noqa: E402
from app.collectors import sources as source_collectors  # noqa: E402
from app.models import Base, Indicator, Source  # noqa: E402
from app.utils.log_safety import code_path, describe_database_error  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# A value a feed listed, and what a caller typed where an address goes.
LISTED = "c2-7f3a9c1e5b2d.example.net"
TYPED = "hunter2-typed-where-an-address-goes"
REQUEST_ID = "req-778-data"
TEAM = "9c858901-8a57-4791-81fe-4c455b099bc9"


# --- The real thing -----------------------------------------------------------------


@pytest.fixture(scope="module")
def postgres():
    server = throwaway_postgres.start_or_skip()
    try:
        yield server.url
    finally:
        server.stop()


def _an_indicator(source_id):
    return Indicator(
        id=uuid.uuid4(),
        source_id=source_id,
        indicator_type="domain",
        value=LISTED,
        normalized_value=LISTED,
        threat_types=["malware"],
        confidence="medium",
        severity=5,
    )


@pytest.fixture(scope="module")
def real_errors(postgres):
    """The errors PostgreSQL and psycopg2 give the service's engine options."""
    engine = create_engine(postgres, hide_parameters=True)
    caught = {}
    try:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        source_id = uuid.uuid4()
        with factory() as session:
            session.add(
                Source(id=source_id, name="a feed", source_type="feodo_tracker")
            )
            session.add(_an_indicator(source_id))
            session.commit()
        try:
            with factory() as session:
                session.add(_an_indicator(source_id))
                session.commit()
        except SQLAlchemyError as error:
            caught["same indicator twice"] = error
        try:
            with engine.connect() as connection:
                connection.execute(
                    text("SELECT CAST(:a AS inet)"),
                    {"a": TYPED},
                )
        except SQLAlchemyError as error:
            caught["text where an address goes"] = error
    finally:
        engine.dispose()
    return caught


def test_postgresql_writes_the_row_in_the_error_of_a_unique_violation(real_errors):
    """The premise: hide_parameters does not cover it."""
    error = real_errors["same indicator twice"]

    assert isinstance(error, IntegrityError)
    assert error.hide_parameters is True
    assert "DETAIL:  Key (source_id, indicator_type, normalized_value)=(" in str(error)
    assert LISTED in str(error)


def test_a_real_unique_violation_is_described_without_the_row(real_errors):
    error = real_errors["same indicator twice"]

    described = describe_database_error(error)

    assert described == (
        "IntegrityError (UniqueViolation, SQLSTATE 23505, "
        "constraint uq_source_indicator, table indicators)"
    )
    assert LISTED not in described + code_path(error)
    assert "test_database_errors_hold_no_values.py" in code_path(error)


def test_a_real_refused_value_is_described_without_the_value(real_errors):
    """Not in DETAIL this time: in the message itself."""
    error = real_errors["text where an address goes"]

    assert isinstance(error, DataError)
    assert f'invalid input syntax for type inet: "{TYPED}"' in str(error)
    described = describe_database_error(error)
    assert described == "DataError (InvalidTextRepresentation, SQLSTATE 22P02)"
    assert TYPED not in described + code_path(error)


# --- Errors of the same shape, without a server ------------------------------------------


class Diagnostics:
    """psycopg2's ``error.diag``."""

    def __init__(self, **fields):
        self.constraint_name = fields.get("constraint")
        self.table_name = fields.get("table")
        self.column_name = fields.get("column")


class UniqueViolation(Exception):
    pgcode = "23505"

    def __init__(self, message):
        super().__init__(message)
        self.diag = Diagnostics(constraint="uq_source_indicator", table="indicators")


class InvalidTextRepresentation(Exception):
    pgcode = "22P02"

    def __init__(self, message):
        super().__init__(message)
        self.diag = Diagnostics()


def unique_violation():
    driver = UniqueViolation(
        'duplicate key value violates unique constraint "uq_source_indicator"\n'
        "DETAIL:  Key (source_id, indicator_type, normalized_value)="
        f"(6f1c0e0a-0000-4000-8000-000000000000, domain, {LISTED}) already exists.\n"
    )
    return IntegrityError(
        "INSERT INTO indicators (id, value) VALUES (%(id)s, %(value)s)",
        {"value": LISTED},
        driver,
        hide_parameters=True,
    )


def refused_value():
    driver = InvalidTextRepresentation(
        f'invalid input syntax for type inet: "{TYPED}"\nLINE 1: ...\n'
    )
    return DataError(
        "SELECT CAST(%(a)s AS inet)",
        {"a": TYPED},
        driver,
        hide_parameters=True,
    )


DESCRIBED = {
    unique_violation: "IntegrityError (UniqueViolation, SQLSTATE 23505, "
    "constraint uq_source_indicator, table indicators)",
    refused_value: "DataError (InvalidTextRepresentation, SQLSTATE 22P02)",
}
VALUE = {unique_violation: LISTED, refused_value: TYPED}
SHAPES = pytest.mark.parametrize(
    "make", [unique_violation, refused_value], ids=["unique violation", "refused value"]
)


def _everything_logged(caplog):
    lines = []
    for record in caplog.records:
        lines.append(record.getMessage())
        if record.exc_info:
            lines.append(logging.Formatter().formatException(record.exc_info))
        if record.exc_text:
            lines.append(record.exc_text)
    return "\n".join(lines)


def _says_nothing_of(value, caplog):
    logged = _everything_logged(caplog)
    assert value not in logged
    for words in ("DETAIL", "already exists", "invalid input syntax"):
        assert words not in logged
    return logged


# --- A route --------------------------------------------------------------------------------


class FailingSession:
    def __init__(self, error):
        self.error = error

    def query(self, *_entities):
        raise self.error


@pytest.fixture
def api():
    user = SimpleNamespace(
        user_id="u", team_id=TEAM, role="member", auth_type="session"
    )
    main.app.dependency_overrides[main.get_current_user] = lambda: user
    client = TestClient(main.app, raise_server_exceptions=False)

    def ask(error, caplog):
        main.app.dependency_overrides[main.get_db] = lambda: FailingSession(error)
        with caplog.at_level(logging.DEBUG):
            return client.get("/api/v1/sources", headers={"X-Request-ID": REQUEST_ID})

    yield ask
    main.app.dependency_overrides.clear()


@SHAPES
def test_a_route_answers_500_and_logs_the_error_without_its_values(api, caplog, make):
    error = make()
    assert VALUE[make] in str(error)

    response = api(error, caplog)

    # The answer the shared handler gave it, and still gives any other error.
    assert response.status_code == 500, response.text
    assert response.json() == {
        "error": {
            "code": 500,
            "message": "An internal error occurred",
            "type": "InternalServerError",
            "request_id": REQUEST_ID,
        }
    }
    _says_nothing_of(VALUE[make], caplog)
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.name == "app.api.main"
    assert record.getMessage().startswith(f"Database error: {DESCRIBED[make]}\n")
    assert record.exc_info is None
    assert record.request_id == REQUEST_ID
    assert record.path == "/api/v1/sources"
    # Where it happened, in the service's code.
    assert "list_sources" in record.getMessage()


def test_a_database_that_cannot_be_reached_is_named_by_its_class(api, caplog):
    """Its answer does not change either: the same 500."""
    error = OperationalError(
        "SELECT 1",
        {},
        Exception('connection to server at "db-7.internal" failed'),
        hide_parameters=True,
    )

    response = api(error, caplog)

    assert response.status_code == 500, response.text
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage().startswith(
        "Database error: OperationalError (Exception)"
    )


def test_an_error_that_is_not_the_databases_still_goes_to_the_shared_handler(
    api, caplog
):
    response = api(ValueError("not a database error"), caplog)

    assert response.status_code == 500
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.name == "open_security_shared.errors"
    # The shared handler's own record: the class of the error and where it
    # was raised, not its text. (This asked for the record's traceback,
    # which ended with the text, until #788.)
    assert record.getMessage().startswith(
        "Unhandled exception: ValueError raised at "
    )
    assert "not a database error" not in record.getMessage()
    assert record.exc_info is None


# --- The collector ----------------------------------------------------------------------------


class RefusingSession:
    """A session that finds no such indicator and refuses the new one."""

    def __init__(self, error):
        self.error = error
        self.rolled_back = 0

    def query(self, *_entities):
        return SimpleNamespace(filter=lambda *_c: SimpleNamespace(first=lambda: None))

    def add(self, _row):
        pass

    def flush(self):
        raise self.error

    def rollback(self):
        self.rolled_back += 1


def _collector():
    source = Source(
        id=uuid.uuid4(),
        name="a feed",
        source_type="feodo_tracker",
        url="https://feeds.example.com/list.json",
        config={},
        headers={},
        rate_limit=100,
        rate_limit_window=60,
        timeout=30,
        collection_interval=3600,
        enabled=True,
        status="active",
    )
    return source_collectors.FeodoTrackerCollector(source)


# One entry of the feed, in its format.
LISTED_ENTRY = {
    "ip_address": "198.51.100.24",
    "port": 8080,
    "status": "online",
    "hostname": None,
    "as_number": 64500,
    "as_name": "EXAMPLE-AS",
    "country": "US",
    "first_seen": "2026-09-30 10:11:12",
    "last_online": "2026-10-06",
    "malware": "QakBot",
}
INDICATOR = {
    "indicator_type": "domain",
    "value": LISTED,
    "normalized_value": LISTED,
    "threat_types": ["malware"],
    "confidence": "medium",
    "severity": 5,
}


@SHAPES
def test_an_indicator_the_database_refuses_is_logged_without_its_values(caplog, make):
    error = make()
    session = RefusingSession(error)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(SQLAlchemyError) as raised:
            asyncio.run(_collector()._store_indicator(session, dict(INDICATOR), {}))

    # The error itself goes on, to fail the collection; the session is clean.
    assert raised.value is error
    assert session.rolled_back == 1
    _says_nothing_of(VALUE[make], caplog)
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage() == f"Error storing indicator: {DESCRIBED[make]}"


def test_an_indicator_that_fails_for_another_reason_is_logged_as_before(caplog):
    session = RefusingSession(ValueError("severity out of range"))

    with caplog.at_level(logging.ERROR):
        with pytest.raises(ValueError):
            asyncio.run(_collector()._store_indicator(session, dict(INDICATOR), {}))

    assert "Error storing indicator: severity out of range" in caplog.text


@SHAPES
def test_a_collection_the_database_fails_is_logged_without_the_traceback_that_repeats_it(
    monkeypatch, caplog, make
):
    """The run fails with the error; its traceback ends with the error's
    text, so it is the frames that are logged, and the class is what is
    stored with the run."""
    error = make()
    collector = _collector()
    stored = {}

    class RunSession:
        def add(self, row):
            stored["run"] = row

        def commit(self):
            pass

        def refresh(self, _row):
            pass

        def close(self):
            pass

    async def collect_data():
        yield dict(LISTED_ENTRY)

    async def refuse(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(collectors, "get_db_session", RunSession)
    monkeypatch.setattr(collector, "collect_data", collect_data)
    monkeypatch.setattr(collector, "_store_indicator", refuse)

    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(collector.run_collection())

    assert result.status.value == "failed"
    assert result.error_message == type(error).__name__
    assert stored["run"].error_message == type(error).__name__
    _says_nothing_of(VALUE[make], caplog)
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage().startswith(
        f"Collection failed for source a feed: {DESCRIBED[make]}\n"
    )
    assert record.exc_info is None
    assert "run_collection" in record.getMessage()


# --- What is written, and what is not -----------------------------------------------------------


def test_a_diagnostic_field_is_written_only_if_it_reads_as_a_name():
    """The fields are the schema's names. One that is not, is not written:
    nothing here trusts a driver to keep values out of them."""
    driver = UniqueViolation("message")
    driver.pgcode = f"Key (value)=({LISTED})"
    driver.diag = Diagnostics(constraint=f"x ({LISTED})", table="indicators")

    described = describe_database_error(
        IntegrityError("INSERT", {}, driver, hide_parameters=True)
    )

    assert described == "IntegrityError (UniqueViolation, table indicators)"


def test_an_error_without_a_driver_error_is_named_by_its_class():
    assert describe_database_error(SQLAlchemyError(f"about {LISTED}")) == (
        "SQLAlchemyError"
    )
