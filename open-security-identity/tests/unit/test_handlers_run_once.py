"""A request is dispatched once, whatever its handler raises.

identity had a middleware, ``db_session_middleware``, that wrapped two things
in one ``try``: making a session for ``request.state.db``, and ``call_next``,
the rest of the application. Its ``except`` clauses were written for the
first ("fail gracefully": go on without a session) and caught the second as
well, so an error a *route* raised (``ValueError``, ``KeyError``,
``TypeError``, ``ConnectionError``, ``TimeoutError``, any ``SQLAlchemyError``)
was answered by calling ``call_next`` again.

What that did, measured on Starlette 1.6: the second ``call_next`` raised the
first error again at once, but the second dispatch had been started. It ran
as far as its first suspension and was cancelled there. In an application
where nothing suspends before the handler, the handler's body ran twice. In
identity a dependency that runs in a worker thread comes first, so the second
run was torn down before any handler: the route tests below, which count a
gateway call and a write, pass with the middleware too. They are here so that
it stays that way. Where the second run stopped was Starlette's to decide,
not this service's; the tests on the middlewares are the ones that fail with
it.

The middleware is gone. The requests below go through the real application
and its real routes; the user store, the database session and the gateway
call are stubs that count.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.database as database  # noqa: E402
import app.main as main  # noqa: E402
from app import user_manager  # noqa: E402
from app.api_v1.endpoints import user_api_keys  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.exc import OperationalError, SQLAlchemyError  # noqa: E402
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.requests import Request  # noqa: E402

KEY_PREFIX = "wsk_ab12"


def retried():
    """What the middleware caught and answered by dispatching the request again."""
    return [
        SQLAlchemyError("commit failed"),
        ValueError("bad value"),
        KeyError("missing"),
        TypeError("wrong type"),
        ConnectionError("reset by peer"),
        TimeoutError("timed out"),
    ]


def named(exc):
    return type(exc).__name__


class Session:
    """A session that finds the caller's team and key, and counts what it is asked."""

    def __init__(self):
        self.team = SimpleNamespace(id=uuid.uuid4())
        self.key = SimpleNamespace(id=uuid.uuid4(), is_active=True)
        self.queries = 0
        self.added = []
        self.commits = 0
        self.commit_failure = None
        self.refresh_failure = None

    async def execute(self, _query):
        # Each route asks for the caller's team, then for the key.
        found = self.team if self.queries % 2 == 0 else self.key
        self.queries += 1
        return SimpleNamespace(scalar_one_or_none=lambda: found)

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.commits += 1
        if self.commit_failure is not None:
            raise self.commit_failure

    async def refresh(self, row):
        if self.refresh_failure is not None:
            raise self.refresh_failure
        row.id = uuid.uuid4()
        row.is_active = True
        row.last_used_at = None
        row.created_at = datetime.now(timezone.utc)

    async def close(self):
        pass


class Store:
    """The user store fastapi-users resolves the token's subject from."""

    def __init__(self, member):
        self.member = member

    async def get(self, user_id):
        return self.member if user_id == self.member.id else None


@pytest.fixture
def identity(monkeypatch):
    """What a test needs: client, headers, session, gateway calls."""
    member = SimpleNamespace(
        id=uuid.uuid4(),
        email="alice@example.com",
        is_active=True,
        is_superuser=False,
        is_verified=True,
        must_change_password=False,
        tokens_valid_after=None,
    )
    session = Session()
    revocations = []

    async def the_manager():
        yield user_manager.UserManager(Store(member))

    async def get_db():
        yield session

    async def not_blacklisted(_jti):
        return False

    async def revoke_at_the_gateway(api_key_ids, _action):
        revocations.append(list(api_key_ids))

    app = main.app
    app.dependency_overrides[user_manager.get_user_manager] = the_manager
    app.dependency_overrides[database.get_db] = get_db
    monkeypatch.setattr(user_manager, "is_token_blacklisted", not_blacklisted)
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    monkeypatch.setattr(user_api_keys, "revoke_api_keys_or_503", revoke_at_the_gateway)
    token = asyncio.run(user_manager.get_jwt_strategy().write_token(member))
    yield SimpleNamespace(
        client=TestClient(app, raise_server_exceptions=False),
        headers={"Authorization": f"Bearer {token}"},
        session=session,
        revocations=revocations,
    )
    app.dependency_overrides.clear()


@pytest.mark.parametrize("failure", retried(), ids=named)
def test_a_revocation_that_fails_after_the_gateway_call_is_dispatched_once(
    identity, failure
):
    identity.session.commit_failure = failure

    response = identity.client.delete(
        f"/api/v1/api-keys/{KEY_PREFIX}", headers=identity.headers
    )

    assert response.status_code == 500
    # What the handler did before it failed, it did once.
    assert identity.revocations == [[identity.session.key.id]]
    assert identity.session.commits == 1


@pytest.mark.parametrize("failure", retried(), ids=named)
def test_a_key_creation_that_fails_after_the_commit_is_dispatched_once(
    identity, failure
):
    identity.session.refresh_failure = failure

    response = identity.client.post(
        "/api/v1/api-keys", headers=identity.headers, json={"name": "ci"}
    )

    assert response.status_code == 500
    # One key written: a second would be an active credential whose secret
    # nobody was ever shown.
    assert len(identity.session.added) == 1
    assert identity.session.commits == 1


def test_a_lost_connection_is_a_503_and_one_dispatch(identity):
    identity.session.commit_failure = OperationalError(
        "COMMIT", {}, Exception("connection refused")
    )

    response = identity.client.delete(
        f"/api/v1/api-keys/{KEY_PREFIX}", headers=identity.headers
    )

    assert response.status_code == 503
    assert "Database temporarily unavailable" in response.text
    assert "connection refused" not in response.text
    assert identity.revocations == [[identity.session.key.id]]
    # Answered inside the application now, so it carries the correlation id.
    assert response.headers.get("X-Request-ID")


def test_a_request_that_succeeds_is_unchanged(identity):
    response = identity.client.delete(
        f"/api/v1/api-keys/{KEY_PREFIX}", headers=identity.headers
    )

    assert response.status_code == 200
    assert identity.revocations == [[identity.session.key.id]]
    assert identity.session.key.is_active is False
    assert identity.session.commits == 1


# --- every middleware the application registers ------------------------------


def http_middlewares():
    """(name, dispatch) of each BaseHTTPMiddleware of the application."""
    found = []
    for entry in main.app.user_middleware:
        if isinstance(entry.cls, type) and issubclass(entry.cls, BaseHTTPMiddleware):
            instance = entry.cls(None, *entry.args, **entry.kwargs)
            dispatch = instance.dispatch_func
            found.append((getattr(dispatch, "__qualname__", repr(dispatch)), dispatch))
    return found


def dispatches(dispatch, failure):
    """How many times ``dispatch`` calls downstream when downstream raises."""
    calls = []

    async def call_next(request):
        calls.append(request)
        raise failure

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/x",
        "headers": [],
        "query_string": b"",
        "state": {},
    }

    async def run():
        try:
            await dispatch(Request(scope), call_next)
        except Exception:  # the outcome is the application's to answer
            pass

    asyncio.run(run())
    return len(calls)


@pytest.mark.parametrize(
    "failure",
    [
        *retried(),
        OperationalError("SELECT 1", {}, Exception("down")),
        RuntimeError("anything else"),
    ],
    ids=named,
)
def test_no_middleware_calls_downstream_twice(failure):
    middlewares = http_middlewares()
    assert middlewares, "the correlation and metrics middleware is expected here"
    for name, dispatch in middlewares:
        assert dispatches(dispatch, failure) == 1, name


def test_the_service_registers_no_http_middleware_of_its_own():
    # The only one is the shared correlation and metrics middleware.
    names = [name for name, _ in http_middlewares()]
    assert names == ["ObservabilityMiddleware.dispatch"]


# --- what the middleware's session was for -----------------------------------


class RegistrationSession:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        for row in self.added:
            if getattr(row, "id", None) is None:
                row.id = uuid.uuid4()

    async def commit(self):
        self.commits += 1


def registered(request):
    """Run the registration hook; return the session it wrote to."""
    session = RegistrationSession()
    manager = user_manager.UserManager(SimpleNamespace(session=session))
    user = SimpleNamespace(id=uuid.uuid4(), email="new@example.com")
    asyncio.run(manager.on_after_register(user, request))
    return session


def test_registration_makes_the_personal_team_without_a_session_on_the_request():
    # The hook looked for request.state.db, which the middleware put there
    # and nothing used: without it, no team was made.
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    assert not hasattr(request.state, "db")

    session = registered(request)

    assert [type(row).__name__ for row in session.added] == ["Team", "TeamMembership"]
    assert session.commits == 1


def test_an_account_created_outside_a_request_gets_no_personal_team():
    # scripts/init.sh creates the first administrator without a request and
    # makes its team itself.
    session = registered(None)

    assert session.added == [] and session.commits == 0
