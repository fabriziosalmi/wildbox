"""identity's /health reports its database and its Redis from real checks (#559).

The admin page showed Database and Redis as healthy whenever identity
answered at all; it now reads them from these checks. The database session
and the Redis client are replaced with stubs, so this needs neither.
"""

import logging
import os
import socket
import sys
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.database as database  # noqa: E402
import app.main as main  # noqa: E402
import app.token_blacklist as token_blacklist  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from redis.exceptions import ConnectionError as RedisConnectionError  # noqa: E402
from sqlalchemy.exc import OperationalError, ProgrammingError  # noqa: E402


class _Session:
    def __init__(self, fail):
        self.fail = fail

    async def execute(self, _statement):
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail:
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    async def close(self):
        pass


class _Redis:
    def __init__(self, fail):
        self.fail = fail

    async def ping(self):
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail:
            raise RedisConnectionError("connection refused")
        return True


@pytest.fixture
def stack(monkeypatch):
    # False, True (the error each check was written for), or the error.
    state = {"db_down": False, "redis_down": False, "no_session": None}

    async def get_db():
        if state["no_session"] is not None:
            raise state["no_session"]
        yield _Session(state["db_down"])

    async def get_redis():
        return _Redis(state["redis_down"])

    # The request middleware opens a session through main's own reference;
    # the handler imports it from app.database at call time.
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    monkeypatch.setattr(token_blacklist, "get_redis", get_redis)
    return state


def _health():
    response = TestClient(main.app).get("/health")
    assert response.status_code == 200
    return response.json()


def test_everything_up(stack):
    body = _health()
    assert body["status"] == "healthy"
    assert body["checks"]["database"]["status"] == "healthy"
    assert body["checks"]["redis"]["status"] == "healthy"


def test_redis_down_degrades_the_service(stack):
    stack["redis_down"] = True
    body = _health()
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["status"] == "healthy"
    assert body["checks"]["redis"] == {"status": "unhealthy"}


def test_database_down_is_unhealthy_whatever_redis_says(stack):
    stack["db_down"] = True
    body = _health()
    assert body["status"] == "unhealthy"
    assert body["checks"]["database"] == {"status": "unhealthy"}
    assert body["checks"]["redis"]["status"] == "healthy"


# --- Errors the checks were not written for (#788) --------------------------------
# The database check caught OperationalError, SQLAlchemyError and five builtin
# classes. A host name that does not resolve raises socket.gaierror, which is
# an OSError and none of those: the driver passes it on as it is, the route
# raised it, and the probe was answered 500 in the error body. Run with
# DATABASE_URL naming a host that does not exist, identity's /health did that.

HOST = "wildbox-postgres.internal"
NOT_RESOLVED = socket.gaierror(8, f"nodename nor servname provided: {HOST}")
OTHER_ERRORS = [
    NOT_RESOLVED,
    OSError(113, f"No route to host {HOST}"),
    RuntimeError(f"the connection pool of {HOST} is closed"),
    AttributeError(f"'NoneType' object has no attribute 'execute' ({HOST})"),
]


@pytest.mark.parametrize("error", OTHER_ERRORS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize("raised_by", ["the query", "the session"])
def test_any_error_of_the_database_check_is_an_unhealthy_database(
    stack, caplog, error, raised_by
):
    stack["db_down" if raised_by == "the query" else "no_session"] = error

    with caplog.at_level(logging.WARNING, logger=main.__name__):
        response = TestClient(main.app, raise_server_exceptions=False).get("/health")

    # main: 500, and the error body.
    assert response.status_code == 200, response.text
    body = response.json()
    # The answer a database that refuses the connection gets.
    assert body["status"] == "unhealthy"
    assert body["checks"]["database"] == {"status": "unhealthy"}
    assert body["checks"]["redis"]["status"] == "healthy"
    assert set(body) == {"status", "service", "timestamp", "checks"}
    # The class is in the log, once; the text is nowhere.
    assert [record.getMessage() for record in caplog.records] == [
        f"Health check: the database check raised {type(error).__name__}"
    ]
    assert HOST not in response.text and HOST not in caplog.text


def test_the_answer_is_the_one_a_refused_connection_gets(stack):
    stack["db_down"] = True
    refused = _health()
    stack["db_down"] = NOT_RESOLVED

    not_resolved = _health()

    for body in (refused, not_resolved):
        body.pop("timestamp")
        body["checks"]["redis"].pop("response_time_ms")
    assert not_resolved == refused


def test_a_database_error_that_is_not_about_the_connection_is_still_degraded(stack):
    stack["db_down"] = ProgrammingError("SELECT 1", {}, Exception("no such table"))

    body = _health()

    assert body["status"] == "degraded"
    assert body["checks"]["database"] == {"status": "degraded"}


@pytest.mark.parametrize(
    "error",
    [RuntimeError(f"no running loop for {HOST}"), ValueError(f"bad URL {HOST}")],
    ids=lambda e: type(e).__name__,
)
def test_any_error_of_the_redis_check_is_an_unhealthy_redis(stack, caplog, error):
    stack["redis_down"] = error

    with caplog.at_level(logging.WARNING, logger=main.__name__):
        response = TestClient(main.app, raise_server_exceptions=False).get("/health")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["redis"] == {"status": "unhealthy"}
    assert body["checks"]["database"]["status"] == "healthy"
    assert [record.getMessage() for record in caplog.records] == [
        f"Health check: the Redis check raised {type(error).__name__}"
    ]
    assert HOST not in response.text and HOST not in caplog.text


def test_the_report_carries_no_connection_details(stack):
    """The gateway exposes this to signed-in users: statuses only."""
    stack["redis_down"] = True
    body = _health()
    text = str(body).lower()
    for detail in ("redis://", "postgresql", "password", "refused"):
        assert detail not in text
