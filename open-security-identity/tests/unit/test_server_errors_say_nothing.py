"""A 500 does not say what went wrong inside; the log does.

Four routes caught an error to answer a 500 of their own, with the text of
the exception in it, in every environment: the three analytics routes
(``Failed to generate ...: {str(e)}``) and the deletion of a user
(``Failed to delete user: {str(e)}``). The text of an exception names
tables, columns, hosts and paths. The routes now leave the error to the
shared handler, which answers the same 500 for every unhandled error and
logs the exception.

The requests go through the real application and its real routes; the user
store, the database session and the gateway call are stubs.
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
from app.api_v1.endpoints import users  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# What an exception says when a query meets a schema it did not expect.
INTERNALS = 'relation "billing_secrets" does not exist at db-7.internal:5432'
REQUEST_ID = "req-735-identity"

ANALYTICS = [
    "/api/v1/analytics/admin/system-stats",
    "/api/v1/analytics/admin/user-activity",
    "/api/v1/analytics/admin/usage-summary",
]


class Session:
    """A session that finds one user to delete and fails where it is told to."""

    def __init__(self):
        self.victim = SimpleNamespace(
            id=uuid.uuid4(),
            email="bob@example.com",
            is_superuser=False,
            owned_teams=[],
            team_memberships=[],
            api_keys=[],
        )
        self.execute_failure = None
        self.commit_failure = None
        self.deleted = []
        self.rollbacks = 0

    async def execute(self, _query):
        if self.execute_failure is not None:
            raise self.execute_failure
        return SimpleNamespace(scalar_one_or_none=lambda: self.victim)

    async def delete(self, row):
        self.deleted.append(row)

    async def commit(self):
        if self.commit_failure is not None:
            raise self.commit_failure

    async def rollback(self):
        self.rollbacks += 1

    async def close(self):
        pass


@pytest.fixture
def identity(monkeypatch):
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

    async def no_keys(*_args, **_kwargs):
        return []

    async def the_gateway_confirms(*_args, **_kwargs):
        return None

    app = main.app
    app.dependency_overrides[user_manager.get_user_manager] = the_manager
    app.dependency_overrides[database.get_db] = get_db
    monkeypatch.setattr(user_manager, "is_token_blacklisted", not_blacklisted)
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    monkeypatch.setattr(users, "active_api_key_ids", no_keys)
    monkeypatch.setattr(users, "end_account_access_or_503", the_gateway_confirms)
    token = asyncio.run(user_manager.get_jwt_strategy().write_token(admin))
    yield SimpleNamespace(
        client=TestClient(app, raise_server_exceptions=False),
        headers={"Authorization": f"Bearer {token}", "X-Request-ID": REQUEST_ID},
        session=session,
    )
    app.dependency_overrides.clear()


def says_nothing(response, caplog):
    """The canonical 500, with nothing of the cause; in the log, the class
    of the error and where it was raised.

    This asked for the text of the error in the log, and for its traceback,
    which ends with the text again: what the shared handler logged until
    #788. The text is what "names tables, columns, hosts and paths", and in
    a route it is made from the request; the log has the class, the place
    and the frames.
    """
    assert response.status_code == 500, response.text
    assert response.json() == {
        "error": {
            "code": 500,
            "message": "An internal error occurred",
            "type": "InternalServerError",
            "request_id": REQUEST_ID,
        }
    }
    for fragment in ("billing_secrets", "db-7.internal", "Failed to", "ValueError"):
        assert fragment not in response.text, fragment
    # Logged once by the shared handler, with the id that the client was
    # given: the class of the error, the place it was raised at (the
    # session's method, here) and the frames, without its text.
    logged = [
        record
        for record in caplog.records
        if record.name == "open_security_shared.errors" and record.levelname == "ERROR"
    ]
    assert len(logged) == 1
    message = logged[0].getMessage()
    assert message.startswith("Unhandled exception: ValueError raised at ")
    first = message.splitlines()[0]
    assert first.endswith((" in execute", " in commit")) and __file__ in first
    for fragment in (INTERNALS, "billing_secrets", "db-7.internal"):
        assert fragment not in message, fragment
    assert logged[0].request_id == REQUEST_ID
    assert logged[0].exc_info is None and logged[0].exc_text is None


@pytest.mark.parametrize("path", ANALYTICS)
def test_an_analytics_route_that_fails_does_not_say_how(identity, caplog, path):
    identity.session.execute_failure = ValueError(INTERNALS)

    with caplog.at_level("ERROR"):
        response = identity.client.get(path, headers=identity.headers)

    says_nothing(response, caplog)


def test_a_deletion_that_fails_does_not_say_how_and_is_rolled_back(identity, caplog):
    identity.session.commit_failure = ValueError(INTERNALS)

    with caplog.at_level("ERROR"):
        response = identity.client.delete(
            f"/api/v1/admin/users/{identity.session.victim.id}",
            headers=identity.headers,
        )

    says_nothing(response, caplog)
    assert identity.session.rollbacks == 1


def test_a_deletion_that_succeeds_is_unchanged(identity):
    response = identity.client.delete(
        f"/api/v1/admin/users/{identity.session.victim.id}", headers=identity.headers
    )

    assert response.status_code == 200
    assert response.json() == {"message": "User bob@example.com deleted successfully"}
    assert identity.session.deleted == [identity.session.victim]
    assert identity.session.rollbacks == 0
