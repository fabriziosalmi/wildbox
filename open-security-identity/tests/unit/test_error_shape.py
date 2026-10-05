"""identity answers the error body every Wildbox service answers (#722).

``install_error_handlers`` gives a FastAPI service the canonical body,

    {"error": {"code": 404, "message": "...", "type": "HTTPException",
               "request_id": "..."}}

and identity installed it, then registered two handlers of its own under it.
``@app.exception_handler(404)`` answered ``{"detail": "Endpoint not found"}``
to every 404, the ones a route raised with its own message included: a
superuser who asked about a user that does not exist was told the endpoint
did not exist. ``@app.exception_handler(500)`` replaced the catch-all with
``{"detail": "Internal server error"}``, which carries no request id, the one
field that ties a failure a user reports to a line of the log. The database
middleware answered a third body, ``{"detail": ...}``, for a lost connection.

The requests below go through the real application and its real routes; only
the user store and the database session are stubs, so no service is needed.
"""

import asyncio
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
from app import user_manager  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402

REQUEST_ID = "req-722-identity"
METRICS = "/api/v1/admin/metrics"


class Session:
    """A database session that finds nothing, or fails as it is told to."""

    def __init__(self, failure=None):
        self.failure = failure

    async def execute(self, _query):
        if self.failure is not None:
            raise self.failure
        return SimpleNamespace(scalar_one_or_none=lambda: None, scalar=lambda: 0)

    async def close(self):
        pass


@pytest.fixture
def identity(monkeypatch):
    """(client, bearer header of a superuser, the session the routes get)."""
    admin = SimpleNamespace(
        id=uuid.uuid4(),
        email="root@example.com",
        is_active=True,
        is_superuser=True,
        is_verified=True,
        must_change_password=False,
        tokens_valid_after=None,
    )
    session = Session()

    class Store:
        async def get(self, user_id):
            return admin if user_id == admin.id else None

    async def the_manager():
        yield user_manager.UserManager(Store())

    async def get_db():
        yield session

    async def not_blacklisted(_jti):
        return False

    app = main.app
    app.dependency_overrides[user_manager.get_user_manager] = the_manager
    # The routes depend on the function the module defined; main looks its
    # own name up at each request.
    app.dependency_overrides[database.get_db] = get_db
    monkeypatch.setattr(user_manager, "is_token_blacklisted", not_blacklisted)
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    token = asyncio.run(user_manager.get_jwt_strategy().write_token(admin))
    headers = {"Authorization": f"Bearer {token}", "X-Request-ID": REQUEST_ID}
    # An unhandled exception is what the 500 tests are about: the client must
    # hand back the response the application makes of it, not re-raise it.
    yield TestClient(app, raise_server_exceptions=False), headers, session
    app.dependency_overrides.clear()


def canonical(response, status):
    """The ``error`` object of a canonical body, checked for its fixed fields."""
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"error"}, body
    error = body["error"]
    assert error["code"] == status
    assert error["request_id"] == REQUEST_ID
    return error


def test_a_404_a_route_raises_keeps_the_message_of_the_route(identity):
    client, headers, _ = identity
    response = client.get(
        f"/api/v1/admin/users/{uuid.uuid4()}/can-delete", headers=headers
    )
    error = canonical(response, 404)
    assert error["message"] == "User not found"
    assert error["type"] == "HTTPException"
    assert "Endpoint not found" not in response.text


def test_an_unknown_path_answers_the_canonical_404(identity):
    client, headers, _ = identity
    response = client.get("/api/v1/no-such-route", headers=headers)
    error = canonical(response, 404)
    assert error["message"] == "Not Found"
    assert error["type"] == "HTTPException"


def test_an_unknown_path_needs_no_credentials_to_be_a_404(identity):
    client, _, _ = identity
    response = client.get("/nowhere", headers={"X-Request-ID": REQUEST_ID})
    assert canonical(response, 404)["message"] == "Not Found"


def test_an_unhandled_exception_answers_the_canonical_500_with_the_request_id(
    identity,
):
    client, headers, session = identity
    session.failure = RuntimeError("relation users_secret_column does not exist")
    response = client.get(METRICS, headers=headers)
    error = canonical(response, 500)
    assert error["type"] == "InternalServerError"
    assert error["message"] == "An internal error occurred"
    # Generic on purpose: the exception text stays in the log.
    assert "users_secret_column" not in response.text
    assert "detail" not in response.json()


def test_the_500_has_a_request_id_when_the_caller_sent_none(identity):
    client, headers, session = identity
    session.failure = RuntimeError("boom")
    response = client.get(METRICS, headers={"Authorization": headers["Authorization"]})
    assert response.status_code == 500
    request_id = response.json()["error"]["request_id"]
    assert request_id and request_id != "unknown"


def test_a_500_a_route_raises_keeps_the_message_of_the_route(identity):
    """/internal/authorize raises HTTPException(500, "Authorization failed")."""
    from fastapi import HTTPException

    client, headers, _ = identity

    async def refuse():
        raise HTTPException(status_code=500, detail="Authorization failed")

    app = main.app
    app.dependency_overrides[user_manager.current_superuser] = refuse
    response = client.get(METRICS, headers=headers)
    error = canonical(response, 500)
    assert error["message"] == "Authorization failed"
    assert error["type"] == "HTTPException"


def test_a_lost_database_connection_answers_the_canonical_503(identity):
    client, headers, session = identity
    session.failure = OperationalError("SELECT 1", {}, Exception("connection refused"))
    response = client.get(
        f"/api/v1/admin/users/{uuid.uuid4()}/can-delete", headers=headers
    )
    error = canonical(response, 503)
    assert error["message"] == "Database temporarily unavailable"
    assert "connection refused" not in response.text


CHANGE_PASSWORD = "/api/v1/admin/me/change-password"


def test_a_new_password_that_is_too_short_is_not_sent_back(identity):
    """FastAPI's field errors carry the refused ``input``: here, the password."""
    client, headers, _ = identity
    response = client.post(
        CHANGE_PASSWORD,
        headers=headers,
        json={"current_password": "the-old-password-1", "new_password": "pw-2short"},
    )
    error = canonical(response, 422)
    assert error["type"] == "ValidationError"
    assert error["details"] == [
        {
            "type": "string_too_short",
            "loc": ["body", "new_password"],
            "msg": "String should have at least 12 characters",
        }
    ]
    assert "pw-2short" not in response.text
    assert "the-old-password-1" not in response.text


def test_a_missing_field_does_not_send_the_other_password_back(identity):
    """``input`` of a missing field is the whole body it is missing from."""
    client, headers, _ = identity
    response = client.post(
        CHANGE_PASSWORD,
        headers=headers,
        json={"new_password": "a-new-password-long-enough"},
    )
    error = canonical(response, 422)
    assert error["details"] == [
        {
            "type": "missing",
            "loc": ["body", "current_password"],
            "msg": "Field required",
        }
    ]
    assert "a-new-password-long-enough" not in response.text


def test_no_handler_is_registered_for_a_status_code():
    """The canonical handlers are per exception class; a handler registered
    for a status code (``@app.exception_handler(404)``) runs before them."""
    by_status = [key for key in main.app.exception_handlers if isinstance(key, int)]
    assert by_status == []
