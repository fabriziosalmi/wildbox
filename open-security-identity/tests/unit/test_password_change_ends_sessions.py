"""A password change ends the account's other sessions (#569).

POST /api/v1/admin/me/change-password (and every other path that sets a
password) updated the hash and nothing else: each token already issued stayed
valid until it expired, so changing the password after a compromise did not
lock the intruder out. Now the change records a per-user cutoff
(users.tokens_valid_after) after the gateway has confirmed it will refuse the
same tokens, and identity refuses them too -- on its own routes
(RevocableJWTStrategy.read_token) and on /internal/authorize. The session
that made the change gets a new token, issued after the cutoff.

The gateway is patched at the HTTP transport, the database by a stub user
store and the lockout by an in-memory counter: no service is needed.
"""

import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import user_manager  # noqa: E402
from app import gateway_cache, internal, logout, token_blacklist  # noqa: E402
from app.api_v1.endpoints import users  # noqa: E402
from app.auth import verify_access_token  # noqa: E402
from app.auth import get_password_hash, token_predates_cutoff  # noqa: E402
from app.config import settings  # noqa: E402
from app.schemas import PasswordChangeRequest, UserUpdate  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi_users import exceptions  # noqa: E402

SECRET = "unit-test-gateway-proof-of-origin"
PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a-brand-new-long-password"


def run(coro):
    return asyncio.run(coro)


def make_user(**fields):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="alice@example.com",
        hashed_password=get_password_hash(PASSWORD),
        is_active=True,
        is_superuser=False,
        is_verified=True,
        tokens_valid_after=None,
    )
    for name, value in fields.items():
        setattr(user, name, value)
    return user


class UserStore:
    """The parts of SQLAlchemyUserDatabase the manager uses, in memory."""

    def __init__(self, *users):
        self.users = {user.id: user for user in users}
        self.writes = []

    async def get(self, user_id):
        return self.users.get(user_id)

    async def get_by_email(self, email):
        return next((u for u in self.users.values() if u.email == email), None)

    async def update(self, user, update_dict):
        self.writes.append(dict(update_dict))
        for name, value in update_dict.items():
            setattr(user, name, value)
        return user


class StoreManager:
    """Just enough of BaseUserManager for JWTStrategy.read_token()."""

    def __init__(self, store):
        self.store = store

    def parse_id(self, value):
        return uuid.UUID(value)

    async def get(self, user_id):
        user = await self.store.get(user_id)
        if user is None:
            raise exceptions.UserNotExists()
        return user


@pytest.fixture
def gateway(monkeypatch):
    """A scripted gateway at the HTTP transport; records what it was sent."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(gateway_cache, "_RETRY_DELAYS", (0, 0))
    state = {"script": [], "bodies": [], "order": []}

    def handler(request):
        state["order"].append("gateway")
        state["bodies"].append(json.loads(request.content))
        outcome = state["script"].pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    real_client = httpx.AsyncClient

    def client(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(gateway_cache.httpx, "AsyncClient", client)
    return state


def users_confirmed(n=1):
    return httpx.Response(200, json={"purged": True, "scope": "users", "revoked": n})


@pytest.fixture(autouse=True)
def no_redis(monkeypatch):
    async def nothing(*_args):
        return False

    for name in ("record_failed_login", "clear_failed_logins", "is_account_locked"):
        monkeypatch.setattr(user_manager, name, nothing)
    monkeypatch.setattr(user_manager, "is_token_blacklisted", nothing)
    monkeypatch.setattr(token_blacklist, "is_token_blacklisted", nothing)


def strategy():
    return user_manager.get_jwt_strategy()


def token_for(user):
    return run(strategy().write_token(user))


def read(token, store):
    return run(strategy().read_token(token, StoreManager(store)))


# -- the cutoff ----------------------------------------------------------------


def test_no_cutoff_refuses_nothing():
    assert not token_predates_cutoff({"iat": 1}, make_user())


def test_a_token_issued_up_to_the_cutoff_is_refused_and_a_later_one_is_not():
    cutoff = datetime(2026, 10, 3, 12, 0, 0, 500000, tzinfo=timezone.utc)
    user = make_user(tokens_valid_after=cutoff)
    assert token_predates_cutoff({"iat": cutoff.timestamp() - 0.25}, user)
    assert token_predates_cutoff({"iat": cutoff.timestamp()}, user)
    assert not token_predates_cutoff({"iat": cutoff.timestamp() + 0.25}, user)


def test_a_token_without_an_iat_cannot_show_it_is_newer():
    user = make_user(tokens_valid_after=datetime.now(timezone.utc))
    assert token_predates_cutoff({}, user)
    assert token_predates_cutoff({"iat": "yesterday"}, user)


def test_a_naive_cutoff_is_read_as_utc():
    cutoff = datetime(2026, 10, 3, 12, 0, 0)
    user = make_user(tokens_valid_after=cutoff)
    aware = cutoff.replace(tzinfo=timezone.utc).timestamp()
    assert token_predates_cutoff({"iat": aware - 1}, user)
    assert not token_predates_cutoff({"iat": aware + 1}, user)


def test_tokens_issued_in_the_same_second_are_told_apart():
    """The iat is fractional, so a cutoff between two tokens of one second
    refuses the first and keeps the second -- the case of the new token
    handed to the session that changed the password."""
    user = make_user()
    store = UserStore(user)
    before = token_for(user)
    user.tokens_valid_after = datetime.now(timezone.utc)
    after = token_for(user)

    iat_before = verify_access_token(before)["iat"]
    iat_after = verify_access_token(after)["iat"]
    assert iat_before != int(iat_before) or iat_after != int(iat_after)
    assert read(before, store) is None
    assert read(after, store) is user


# -- identity's own routes and /internal/authorize -----------------------------


def test_identity_refuses_a_session_issued_before_the_change():
    user = make_user()
    store = UserStore(user)
    token = token_for(user)
    assert read(token, store) is user

    user.tokens_valid_after = datetime.now(timezone.utc)
    assert read(token, store) is None


class AuthorizeSession:
    def __init__(self, user):
        team = SimpleNamespace(id=uuid.uuid4())
        membership = SimpleNamespace(role="owner")
        self.row = (user, team, membership)

    async def execute(self, _query):
        return SimpleNamespace(first=lambda: self.row)


def authorize(token, user, monkeypatch):
    monkeypatch.setattr(settings, "gateway_internal_secret", SECRET)
    request = internal.TokenAuthRequest(token=token, token_type="bearer")
    return run(
        internal.authorize_request(
            request, db=AuthorizeSession(user), x_gateway_secret=SECRET
        )
    )


def test_the_gateway_is_told_no_for_a_session_issued_before_the_change(monkeypatch):
    user = make_user()
    old = token_for(user)
    assert authorize(old, user, monkeypatch).is_authenticated

    user.tokens_valid_after = datetime.now(timezone.utc)
    new = token_for(user)
    with pytest.raises(HTTPException) as exc:
        authorize(old, user, monkeypatch)
    assert exc.value.status_code == 401
    assert authorize(new, user, monkeypatch).user_id == str(user.id)


# -- every path that sets a password ends the sessions --------------------------


def manager_for(*users_):
    store = UserStore(*users_)
    return user_manager.UserManager(store), store


def test_setting_a_password_tells_the_gateway_first_then_stores_the_cutoff(gateway):
    user = make_user()
    manager, store = manager_for(user)
    real_update = store.update

    async def update(target, update_dict):
        gateway["order"].append("database")
        return await real_update(target, update_dict)

    store.update = update
    gateway["script"] = [users_confirmed()]

    started = time.time()
    run(manager.set_password(user, NEW_PASSWORD))

    assert gateway["order"] == ["gateway", "database"]
    (body,) = gateway["bodies"]
    (entry,) = body["users"]
    assert entry["user_id"] == str(user.id)
    assert body["ttl"] == settings.jwt_access_token_expire_minutes * 60
    (write,) = store.writes
    assert write["tokens_valid_after"].timestamp() == pytest.approx(
        entry["not_before"], abs=1e-6
    )
    assert started <= entry["not_before"] <= time.time()
    assert "hashed_password" in write


def test_the_password_is_not_changed_when_the_gateway_does_not_confirm(gateway):
    user = make_user()
    manager, store = manager_for(user)
    old_hash = user.hashed_password
    # An older gateway: it flushes its cache and counts nothing.
    gateway["script"] = [
        httpx.Response(200, json={"purged": True, "scope": "all", "revoked": 0})
    ] * 3

    with pytest.raises(HTTPException) as exc:
        run(manager.set_password(user, NEW_PASSWORD))
    assert exc.value.status_code == 503
    assert store.writes == []
    assert user.hashed_password == old_hash
    assert user.tokens_valid_after is None


def test_an_update_without_a_password_ends_no_session(gateway):
    other = make_user(email="bob@example.com")
    manager, store = manager_for(other)
    run(manager.update(UserUpdate(is_verified=False), other, safe=False))
    assert gateway["bodies"] == []
    assert "tokens_valid_after" not in store.writes[0]


def test_an_administrators_reset_ends_the_accounts_sessions(gateway):
    other = make_user(email="bob@example.com")
    manager, store = manager_for(other)
    token = token_for(other)
    gateway["script"] = [users_confirmed()]

    run(manager.update(UserUpdate(password=NEW_PASSWORD), other, safe=False))

    assert gateway["bodies"][0]["users"][0]["user_id"] == str(other.id)
    assert read(token, store) is None


def test_the_reset_password_flow_ends_the_accounts_sessions(gateway):
    user = make_user()
    manager, store = manager_for(user)
    session = token_for(user)
    reset_tokens = []

    async def capture(self, user, token, request=None):
        reset_tokens.append(token)

    manager.on_after_forgot_password = capture.__get__(manager)
    run(manager.forgot_password(user))
    gateway["script"] = [users_confirmed()]

    run(manager.reset_password(reset_tokens[0], NEW_PASSWORD))

    assert gateway["bodies"][0]["users"][0]["user_id"] == str(user.id)
    assert user.tokens_valid_after is not None
    assert read(session, store) is None


# -- change-password -----------------------------------------------------------


def test_change_password_ends_the_old_session_and_hands_over_a_new_one(gateway):
    user = make_user()
    manager, store = manager_for(user)
    other_session = token_for(user)
    this_session = token_for(user)
    gateway["script"] = [users_confirmed()]

    answer = run(
        users.change_my_password(
            PasswordChangeRequest(current_password=PASSWORD, new_password=NEW_PASSWORD),
            current_user=user,
            user_manager=manager,
        )
    )

    assert answer["token_type"] == "bearer"
    assert read(other_session, store) is None
    assert read(this_session, store) is None
    assert read(answer["access_token"], store) is user
    assert verify_access_token(answer["access_token"])["sub"] == str(user.id)


def test_the_gateway_marker_lasts_as_long_as_a_token_can(gateway):
    gateway["script"] = [users_confirmed()]
    when = datetime.now(timezone.utc) - timedelta(seconds=1)
    run(logout.revoke_sessions_issued_before("u-1", when))
    body = gateway["bodies"][0]
    assert body == {
        "users": [{"user_id": "u-1", "not_before": when.timestamp()}],
        "ttl": settings.jwt_access_token_expire_minutes * 60,
    }


def test_a_gateway_that_answers_for_another_scope_is_not_trusted(gateway):
    gateway["script"] = [
        httpx.Response(200, json={"purged": True, "scope": "jtis", "revoked": 1})
    ] * 3
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_sessions_issued_before("u-1", datetime.now(timezone.utc)))
