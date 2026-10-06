"""A database error is logged without the values PostgreSQL writes in it (#778).

``hide_parameters`` on the engine (#755) removes the bound parameters from
the text of a SQLAlchemy error. The message the server wrote is still in
that text, and PostgreSQL writes values in its messages::

    duplicate key value violates unique constraint "ix_users_email"
    DETAIL:  Key (email)=(alice@example.com) already exists.

A database error no route caught went to the shared handler, which logs the
exception's text and its traceback: the address, in the service's log, twice.

The first tests make the error for real: the service's own ``users`` table
on a PostgreSQL server, through the driver the service uses. They need
Docker (throwaway_postgres.py). The others give the application an error of
the same shape and run everywhere.
"""

import asyncio
import logging
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.database as database  # noqa: E402
import app.main as main  # noqa: E402
import throwaway_postgres  # noqa: E402
from app import user_manager  # noqa: E402
from app.db_errors import code_path, describe_database_error  # noqa: E402
from app.models import Base, User  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import (  # noqa: E402
    DataError,
    DBAPIError,
    IntegrityError,
    OperationalError,
    SQLAlchemyError,
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # noqa: E402

ADDRESS = "alice-7f3a9c1e@example.com"
# What a caller typed where an id was expected.
TYPED = "hunter2-pasted-where-an-id-goes"
REQUEST_ID = "req-778-identity"
ROUTE = "/api/v1/analytics/admin/system-stats"


# --- The real thing -----------------------------------------------------------------


@pytest.fixture(scope="module")
def postgres():
    server = throwaway_postgres.start_or_skip()
    try:
        yield server.url.replace("postgresql://", "postgresql+asyncpg://", 1)
    finally:
        server.stop()


def _a_user():
    return User(
        id=uuid.uuid4(),
        email=ADDRESS,
        hashed_password="not-a-hash",
        is_active=True,
        is_superuser=False,
        is_verified=False,
    )


async def _errors_of(url):
    """The errors PostgreSQL and asyncpg give the service's own engine options."""
    engine = create_async_engine(url, hide_parameters=True)
    caught = {}
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.drop_all)
            await connection.run_sync(Base.metadata.create_all)
        async with AsyncSession(engine) as session:
            session.add(_a_user())
            await session.commit()
        try:
            async with AsyncSession(engine) as session:
                session.add(_a_user())
                await session.commit()
        except SQLAlchemyError as error:
            caught["same address twice"] = error
        try:
            async with engine.connect() as connection:
                await connection.execute(
                    text("SELECT id FROM users WHERE id = CAST(:id AS uuid)"),
                    {"id": TYPED},
                )
        except SQLAlchemyError as error:
            caught["text where an id goes"] = error
    finally:
        await engine.dispose()
    return caught


@pytest.fixture(scope="module")
def real_errors(postgres):
    return asyncio.run(_errors_of(postgres))


def test_postgresql_writes_the_address_in_the_error_of_a_unique_violation(real_errors):
    """The premise: hide_parameters does not cover it."""
    error = real_errors["same address twice"]

    assert isinstance(error, IntegrityError)
    assert error.hide_parameters is True
    assert f"Key (email)=({ADDRESS}) already exists" in str(error)


def test_a_real_unique_violation_is_described_without_the_address(real_errors):
    error = real_errors["same address twice"]

    described = describe_database_error(error)

    assert described == (
        "IntegrityError (UniqueViolationError, SQLSTATE 23505, "
        "constraint ix_users_email, table users)"
    )
    assert ADDRESS not in described + code_path(error)
    assert "test_database_errors_hold_no_values.py" in code_path(error)


def test_a_real_refused_value_is_described_without_the_value(real_errors):
    """Not in DETAIL this time: in the message itself."""
    error = real_errors["text where an id goes"]

    assert isinstance(error, DBAPIError)
    assert TYPED in str(error)
    described = describe_database_error(error)
    assert TYPED not in described + code_path(error)
    assert described.startswith(f"{type(error).__name__} (")


# --- Through the application ----------------------------------------------------------


class AdaptedError(Exception):
    """SQLAlchemy's adapter for an asyncpg error: the text, and the code."""

    def __init__(self, message, sqlstate):
        super().__init__(message)
        self.sqlstate = self.pgcode = sqlstate


class UniqueViolationError(Exception):
    """asyncpg's own exception, the adapter's cause, with its fields."""

    sqlstate = "23505"
    constraint_name = "ix_users_email"
    table_name = "users"
    column_name = None
    detail = f"Key (email)=({ADDRESS}) already exists."


def unique_violation():
    message = (
        "<class 'asyncpg.exceptions.UniqueViolationError'>: duplicate key value "
        'violates unique constraint "ix_users_email"\n'
        f"DETAIL:  Key (email)=({ADDRESS}) already exists."
    )
    adapted = AdaptedError(message, "23505")
    adapted.__cause__ = UniqueViolationError(message)
    return IntegrityError(
        "INSERT INTO users (id, email) VALUES ($1::UUID, $2::VARCHAR)",
        {"email": ADDRESS},
        adapted,
        hide_parameters=True,
    )


def refused_value():
    message = (
        "<class 'asyncpg.exceptions.DataError'>: invalid input for query argument "
        f"$1: '{TYPED}' (invalid UUID '{TYPED}')"
    )
    return DataError(
        "SELECT id FROM users WHERE id = $1::UUID",
        {"id": TYPED},
        AdaptedError(message, None),
        hide_parameters=True,
    )


@pytest.fixture
def identity(monkeypatch):
    """The real application, an administrator, and a session that fails."""
    admin = SimpleNamespace(
        id=uuid.uuid4(),
        email="root@example.com",
        is_active=True,
        is_superuser=True,
        is_verified=True,
        must_change_password=False,
        tokens_valid_after=None,
    )
    failure = {}

    class Session:
        async def execute(self, _query):
            raise failure["error"]

        async def close(self):
            pass

    class Store:
        async def get(self, user_id):
            return admin if user_id == admin.id else None

    async def the_manager():
        yield user_manager.UserManager(Store())

    async def get_db():
        yield Session()

    async def not_blacklisted(_jti):
        return False

    app = main.app
    app.dependency_overrides[user_manager.get_user_manager] = the_manager
    app.dependency_overrides[database.get_db] = get_db
    monkeypatch.setattr(user_manager, "is_token_blacklisted", not_blacklisted)
    token = asyncio.run(user_manager.get_jwt_strategy().write_token(admin))
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {token}", "X-Request-ID": REQUEST_ID}

    def ask(error, caplog):
        failure["error"] = error
        with caplog.at_level(logging.DEBUG):
            return client.get(ROUTE, headers=headers)

    yield ask
    app.dependency_overrides.clear()


def _everything_logged(caplog):
    lines = []
    for record in caplog.records:
        lines.append(record.getMessage())
        if record.exc_info:
            lines.append(logging.Formatter().formatException(record.exc_info))
        if record.exc_text:
            lines.append(record.exc_text)
    return "\n".join(lines)


@pytest.mark.parametrize(
    "make, value, described",
    [
        (
            unique_violation,
            ADDRESS,
            "IntegrityError (UniqueViolationError, SQLSTATE 23505, "
            "constraint ix_users_email, table users)",
        ),
        (refused_value, TYPED, "DataError (AdaptedError)"),
    ],
    ids=["unique violation", "refused value"],
)
def test_a_database_error_is_answered_500_and_logged_without_its_values(
    identity, caplog, make, value, described
):
    error = make()
    assert value in str(error)

    response = identity(error, caplog)

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
    logged = _everything_logged(caplog)
    assert value not in logged
    assert "DETAIL" not in logged and "already exists" not in logged
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.name == "app.main"
    assert record.getMessage().startswith(f"Database error: {described}\n")
    assert record.exc_info is None
    assert record.request_id == REQUEST_ID
    assert record.path == ROUTE
    # Where it happened, in the service's code.
    assert "analytics.py" in record.getMessage()


def test_a_database_that_cannot_be_reached_is_still_a_503_with_its_cause_logged(
    identity, caplog
):
    """Unchanged: what an OperationalError says is about the connection."""
    cause = "connection to db-7.internal:5432 refused"
    error = OperationalError("SELECT 1", {}, Exception(cause), hide_parameters=True)

    response = identity(error, caplog)

    assert response.status_code == 503, response.text
    assert response.json()["error"]["message"] == "Database temporarily unavailable"
    assert cause in _everything_logged(caplog)
    assert cause not in response.text


def test_an_error_that_is_not_the_databases_still_goes_to_the_shared_handler(
    identity, caplog
):
    response = identity(ValueError("not a database error"), caplog)

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


# --- What is written, and what is not ---------------------------------------------------


def test_a_diagnostic_field_is_written_only_if_it_reads_as_a_name():
    """The fields are the schema's names. One that is not, is not written:
    nothing here trusts a driver to keep values out of them."""
    adapted = AdaptedError("message", f"Key (email)=({ADDRESS})")
    cause = UniqueViolationError("message")
    cause.constraint_name = f"x ({ADDRESS})"
    cause.table_name = "users"
    cause.sqlstate = None
    adapted.__cause__ = cause

    described = describe_database_error(
        IntegrityError("INSERT", {}, adapted, hide_parameters=True)
    )

    assert described == "IntegrityError (UniqueViolationError, table users)"


def test_an_error_without_a_driver_error_is_named_by_its_class():
    assert describe_database_error(SQLAlchemyError(f"about {ADDRESS}")) == (
        "SQLAlchemyError"
    )
