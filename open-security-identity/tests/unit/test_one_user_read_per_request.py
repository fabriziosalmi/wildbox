"""An authenticated request reads its user once, and is refused as before (#665).

Two dependencies resolve the bearer token of a request to an authenticated
route: the route's own (``current_active_user`` or ``current_superuser``) and
``require_password_changed``, attached to the router. fastapi-users makes a
separate dependency of each, so each asked Redis whether the token was
revoked and read the user from the database: two round trips of each kind
for every request.

The strategy now remembers what it read, for the request it was made for.
These tests count the reads, and prove that nothing a request is refused
for has moved: a revoked token, a token older than a password change, an
inactive account, an account that is not a superuser, an account that must
change its password, and a token revoked between two requests.

The tokens are real, read back by the real fastapi-users dependencies; only
the user store, the blacklist and the database session are stubs.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.database as database  # noqa: E402
import app.main as main  # noqa: E402
from app import user_manager  # noqa: E402
from app.auth import verify_access_token  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

METRICS = "/api/v1/admin/metrics"  # current_superuser + require_password_changed
ME = "/api/v1/users/me"  # fastapi-users' own route + require_password_changed


def make_user(**fields):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="alice@example.com",
        is_active=True,
        is_superuser=True,
        is_verified=True,
        must_change_password=False,
        tokens_valid_after=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        team_memberships=[],
    )
    for name, value in fields.items():
        setattr(user, name, value)
    return user


class UserStore:
    """What fastapi-users reads to resolve a token's subject; counts the reads."""

    def __init__(self):
        self.users = {}
        self.reads = []

    def add(self, user):
        self.users[user.id] = user
        return user

    async def get(self, user_id):
        self.reads.append(user_id)
        return self.users.get(user_id)


class Blacklist:
    """Redis' revoked-token set; counts the lookups."""

    def __init__(self):
        self.revoked = set()
        self.lookups = []

    async def __call__(self, jti):
        self.lookups.append(jti)
        return jti in self.revoked


class Counts:
    """A session that answers every count query with 7."""

    async def execute(self, _query):
        return SimpleNamespace(scalar=lambda: 7)

    async def close(self):
        pass


@pytest.fixture
def stack(monkeypatch):
    store, blacklist = UserStore(), Blacklist()

    async def the_manager():
        yield user_manager.UserManager(store)

    async def get_db():
        yield Counts()

    monkeypatch.setattr(user_manager, "is_token_blacklisted", blacklist)
    monkeypatch.setattr(main, "get_db", get_db)
    monkeypatch.setattr(database, "get_db", get_db)
    app = main.app
    app.dependency_overrides[user_manager.get_user_manager] = the_manager
    yield SimpleNamespace(http=TestClient(app), store=store, blacklist=blacklist)
    app.dependency_overrides.clear()


def token_for(user):
    return asyncio.run(user_manager.get_jwt_strategy().write_token(user))


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# -- one read ------------------------------------------------------------------


@pytest.mark.parametrize("path", [METRICS, ME])
def test_an_authenticated_request_reads_its_user_once(stack, path):
    user = stack.store.add(make_user())

    response = stack.http.get(path, headers=bearer(token_for(user)))

    assert response.status_code == 200, response.text
    assert stack.store.reads == [user.id]
    assert len(stack.blacklist.lookups) == 1


def test_every_request_reads_its_user_again(stack):
    """What was read for one request is not kept for the next."""
    user = stack.store.add(make_user())
    token = token_for(user)

    for _ in range(3):
        assert stack.http.get(METRICS, headers=bearer(token)).status_code == 200

    assert stack.store.reads == [user.id] * 3
    assert len(stack.blacklist.lookups) == 3


def test_a_strategy_reads_each_token_it_is_given():
    """Two tokens through one strategy are two users, not the first one twice."""
    first, second = make_user(), make_user(email="bob@example.com")
    store = UserStore()
    store.add(first)
    store.add(second)

    async def not_blacklisted(_jti):
        return False

    async def read_both():
        strategy = user_manager.get_jwt_strategy()
        manager = user_manager.UserManager(store)
        one = await strategy.write_token(first)
        two = await strategy.write_token(second)
        return (
            await strategy.read_token(one, manager),
            await strategy.read_token(two, manager),
            await strategy.read_token(one, manager),
        )

    original = user_manager.is_token_blacklisted
    user_manager.is_token_blacklisted = not_blacklisted
    try:
        assert asyncio.run(read_both()) == (first, second, first)
    finally:
        user_manager.is_token_blacklisted = original
    assert store.reads == [first.id, second.id]


# -- the same refusals -----------------------------------------------------------


def test_a_request_without_a_token_is_refused_without_a_read(stack):
    assert stack.http.get(METRICS).status_code == 401
    assert stack.store.reads == [] and stack.blacklist.lookups == []


def test_a_revoked_token_is_refused_and_no_user_is_read(stack):
    user = stack.store.add(make_user())
    token = token_for(user)
    stack.blacklist.revoked.add(verify_access_token(token)["jti"])

    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 401
    assert stack.http.get(ME, headers=bearer(token)).status_code == 401
    assert stack.store.reads == []
    assert len(stack.blacklist.lookups) == 2  # one per request


def test_a_token_revoked_between_two_requests_is_refused_on_the_second(stack):
    user = stack.store.add(make_user())
    token = token_for(user)

    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 200
    stack.blacklist.revoked.add(verify_access_token(token)["jti"])
    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 401


def test_a_token_older_than_the_password_change_is_refused(stack):
    user = stack.store.add(make_user())
    token = token_for(user)
    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 200

    user.tokens_valid_after = datetime.now(timezone.utc) + timedelta(seconds=5)

    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 401
    assert stack.http.get(ME, headers=bearer(token)).status_code == 401


def test_an_account_deactivated_between_two_requests_is_refused(stack):
    user = stack.store.add(make_user())
    token = token_for(user)
    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 200

    user.is_active = False

    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 401
    assert stack.http.get(ME, headers=bearer(token)).status_code == 401


def test_an_account_that_no_longer_exists_is_refused(stack):
    token = token_for(make_user())  # never added to the store
    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 401


def test_an_account_that_is_not_a_superuser_is_refused_the_superuser_route(stack):
    user = stack.store.add(make_user(is_superuser=False))
    token = token_for(user)

    assert stack.http.get(METRICS, headers=bearer(token)).status_code == 403
    assert stack.http.get(ME, headers=bearer(token)).status_code == 200
    assert stack.store.reads == [user.id] * 2  # one per request


def test_an_account_that_must_change_its_password_is_refused(stack):
    """The router's dependency still decides on the user the route's one read."""
    user = stack.store.add(make_user(must_change_password=True))
    token = token_for(user)

    refused = stack.http.get(METRICS, headers=bearer(token))
    assert refused.status_code == 403
    assert user_manager.PASSWORD_CHANGE_REQUIRED in refused.text
    # GET /users/me is one of the routes such an account may still call.
    assert stack.http.get(ME, headers=bearer(token)).status_code == 200
    assert stack.store.reads == [user.id] * 2
