"""One password policy for every path that sets a password (#583).

fastapi-users' BaseUserCreate does not check the password and its
validate_password() is a no-op, so registration and the reset-password flow
accepted a one-character password while change-password asked for 12. The
policy now lives in UserManager.validate_password() (app/password_policy.py):
12 to 128 characters, not containing the account's email or its local part,
not one of the most common passwords.

Each path is driven through the real UserManager over an in-memory user
store; the gateway revocation a password change waits for is stubbed. Remove
the policy and every refusal below fails.
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

from app import password_policy, user_manager  # noqa: E402
from app.api_v1.endpoints import users  # noqa: E402
from app.auth import get_password_hash  # noqa: E402
from app.schemas import (  # noqa: E402
    PasswordChangeRequest,
    TeamMemberCreate,
    UserCreate,
    UserRead,
    UserUpdate,
)
from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from fastapi_users import exceptions  # noqa: E402
from open_security_shared.errors import install_error_handlers  # noqa: E402
from pydantic import ValidationError  # noqa: E402

EMAIL = "alice.liddell@example.com"
CURRENT = "the current password, long enough"
VALID = "violet-harbor-lantern-42"

# (password, what the reason must mention)
REFUSED = [
    ("a", "at least 12"),
    ("short-pass1", "at least 12"),
    ("x" * 129, "at most 128"),
    (EMAIL, "email"),
    (f"my-{EMAIL.upper()}-pw", "email"),
    ("Alice.Liddell-2026!", "email"),  # the local part, another case
    ("password1234", "common"),
    ("QWERTY123456", "common"),  # the deny-list ignores case
]


def run(coro):
    return asyncio.run(coro)


def make_user(**fields):
    now = datetime.now(timezone.utc)
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email=EMAIL,
        hashed_password=get_password_hash(CURRENT),
        is_active=True,
        is_superuser=False,
        is_verified=True,
        tokens_valid_after=None,
        created_at=now,
        updated_at=now,
    )
    for name, value in fields.items():
        setattr(user, name, value)
    return user


class StoreSession:
    """The session of the store, for the hook that makes a personal team."""

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


class UserStore:
    """The parts of SQLAlchemyUserDatabase the manager uses, in memory."""

    def __init__(self, *accounts):
        self.users = {account.id: account for account in accounts}
        self.writes = []
        self.session = StoreSession()

    async def get(self, user_id):
        return self.users.get(user_id)

    async def get_by_email(self, email):
        return next(
            (u for u in self.users.values() if u.email.lower() == email.lower()), None
        )

    async def create(self, create_dict):
        account = make_user(**create_dict)
        self.users[account.id] = account
        self.writes.append(dict(create_dict))
        return account

    async def update(self, account, update_dict):
        self.writes.append(dict(update_dict))
        for name, value in update_dict.items():
            setattr(account, name, value)
        return account


@pytest.fixture(autouse=True)
def gateway_confirms(monkeypatch):
    """A password change waits for the gateway to end the sessions."""

    async def revoke(user_id, not_before):
        return None

    monkeypatch.setattr(user_manager, "revoke_sessions_issued_before", revoke)


@pytest.fixture
def account():
    return make_user()


@pytest.fixture
def store(account):
    return UserStore(account)


@pytest.fixture
def manager(store):
    return user_manager.UserManager(store)


def assert_refused(call, mention, store):
    with pytest.raises(exceptions.InvalidPasswordException) as exc:
        run(call())
    assert mention in exc.value.reason.lower()
    assert not any(
        "hashed_password" in write for write in store.writes
    ), "a refused password must not be stored"


# --- the rule ---------------------------------------------------------------


@pytest.mark.parametrize("password,mention", REFUSED)
def test_the_policy_refuses(password, mention):
    reason = password_policy.password_problem(password, [EMAIL])
    assert reason is not None and mention in reason.lower()


@pytest.mark.parametrize(
    "password",
    [
        VALID,
        "mq4-vt8-rx2c",
        "mq4-vt8-rx2c" * 10 + "abcdefgh",
        "correct horse battery staple",
    ],
)
def test_the_policy_accepts(password):
    assert password_policy.password_problem(password, [EMAIL]) is None


def test_a_short_local_part_is_not_looked_for():
    # "jo@example.com" must not refuse every password containing "jo".
    assert (
        password_policy.password_problem("jolly-octopus-garden", ["jo@example.com"])
        is None
    )
    assert (
        password_policy.password_problem("jolly-octopus-garden", ["jolly@example.com"])
        is not None
    )


def test_there_are_no_composition_rules():
    # NIST SP 800-63B: no forced character classes.
    assert password_policy.password_problem("lowercase only but long", [EMAIL]) is None


def test_the_deny_list_is_vendored_and_loaded():
    common = password_policy.common_passwords()
    assert len(common) == 10_000
    assert all(len(entry) >= password_policy.MIN_PASSWORD_LENGTH for entry in common)
    assert not any(entry.startswith("#") for entry in common)


# --- every path that sets a password ----------------------------------------


@pytest.mark.parametrize("password,mention", REFUSED)
def test_registration_refuses(manager, store, password, mention):
    assert_refused(
        lambda: manager.create(UserCreate(email=EMAIL, password=password)),
        mention,
        store,
    )


def test_registration_accepts_a_valid_password(manager, store):
    store.users.clear()
    created = run(manager.create(UserCreate(email=EMAIL, password=VALID)))
    assert created.email == EMAIL


def reset_token(manager, account):
    tokens = []

    async def capture(user, token, request=None):
        tokens.append(token)

    manager.on_after_forgot_password = capture
    run(manager.forgot_password(account))
    return tokens[0]


@pytest.mark.parametrize("password,mention", REFUSED)
def test_reset_password_refuses(manager, store, account, password, mention):
    token = reset_token(manager, account)
    assert_refused(lambda: manager.reset_password(token, password), mention, store)


def test_reset_password_accepts_a_valid_password(manager, account):
    token = reset_token(manager, account)
    run(manager.reset_password(token, VALID))
    assert user_manager.verify_password(VALID, account.hashed_password)


@pytest.mark.parametrize("password,mention", REFUSED)
def test_change_password_refuses(manager, store, account, password, mention):
    assert_refused(lambda: manager.set_password(account, password), mention, store)


@pytest.mark.parametrize("password,mention", REFUSED)
def test_superuser_reset_of_another_account_refuses(
    manager, store, account, password, mention
):
    assert_refused(
        lambda: manager.update(UserUpdate(password=password), account, safe=False),
        mention,
        store,
    )


def test_superuser_reset_checks_the_new_email_too(manager, store, account):
    # The email and the password changed in one PATCH: the password must not
    # contain the address the account is about to have.
    update = UserUpdate(email="mad.hatter@example.com", password="mad.hatter-tea-party")
    assert_refused(lambda: manager.update(update, account, safe=False), "email", store)


def test_superuser_reset_accepts_a_valid_password(manager, account):
    run(manager.update(UserUpdate(password=VALID), account, safe=False))
    assert user_manager.verify_password(VALID, account.hashed_password)


class TeamSession:
    """The session create_team_member() writes the account through (#573)."""

    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    async def commit(self):
        return None

    async def refresh(self, _obj):
        return None


class TeamUserDb:
    def __init__(self):
        self.session = TeamSession()

    async def get_by_email(self, email):
        return None


@pytest.mark.parametrize("password,mention", REFUSED)
def test_a_team_administrator_creating_a_member_is_refused(password, mention):
    user_db = TeamUserDb()
    manager = user_manager.UserManager(user_db)
    with pytest.raises(exceptions.InvalidPasswordException) as exc:
        run(manager.create_team_member(EMAIL, password, uuid.uuid4(), "member"))
    assert mention in exc.value.reason.lower()
    assert user_db.session.added == [], "nothing is written for a refused password"


def test_a_team_administrator_creating_a_member_with_a_valid_password():
    user_db = TeamUserDb()
    manager = user_manager.UserManager(user_db)
    created = run(manager.create_team_member(EMAIL, VALID, uuid.uuid4(), "member"))
    assert user_manager.verify_password(VALID, created.hashed_password)


def test_the_member_schema_matches_the_length_rule():
    with pytest.raises(ValidationError):
        TeamMemberCreate(email=EMAIL, password="x" * 129)
    TeamMemberCreate(email=EMAIL, password="x" * 12)


# --- the HTTP answers --------------------------------------------------------


@pytest.fixture
def client(manager):
    # With identity's error handlers: the dashboard reads error.message.
    app = FastAPI()
    install_error_handlers(app)
    app.include_router(
        user_manager.fastapi_users.get_register_router(UserRead, UserCreate),
        prefix="/auth",
    )
    app.include_router(
        user_manager.fastapi_users.get_reset_password_router(), prefix="/auth"
    )

    async def the_manager():
        yield manager

    app.dependency_overrides[user_manager.get_user_manager] = the_manager
    return TestClient(app)


@pytest.mark.parametrize(
    "password,mention",
    [("a", "at least 12"), ("password1234", "common"), (EMAIL, "email")],
)
def test_register_answers_400_with_the_reason(client, store, password, mention):
    store.users.clear()
    response = client.post(
        "/auth/register", json={"email": EMAIL, "password": password}
    )
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["details"]["code"] == "REGISTER_INVALID_PASSWORD"
    assert mention in error["message"].lower()


def test_register_answers_201_for_a_valid_password(client, store):
    store.users.clear()
    response = client.post("/auth/register", json={"email": EMAIL, "password": VALID})
    assert response.status_code == 201, response.text
    # Registration makes the account's personal team. This application has
    # no middleware, and the hook used to return without making one unless a
    # middleware had put a session on the request (#735).
    made = [type(row).__name__ for row in store.session.added]
    assert made == ["Team", "TeamMembership"]
    assert store.session.commits == 1


def test_reset_password_answers_400_with_the_reason(client, manager, account):
    token = reset_token(manager, account)
    response = client.post(
        "/auth/reset-password", json={"token": token, "password": "short"}
    )
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["details"]["code"] == "RESET_PASSWORD_INVALID_PASSWORD"
    assert "at least 12" in error["message"]


def test_change_password_route_answers_400_with_the_reason(
    manager, account, monkeypatch
):
    async def password_ok(user, password):
        return None

    monkeypatch.setattr(users, "verify_current_password", password_ok)
    request = PasswordChangeRequest(
        current_password=CURRENT, new_password="password1234"
    )
    with pytest.raises(HTTPException) as exc:
        run(
            users.change_my_password(
                request, current_user=account, user_manager=manager
            )
        )
    assert exc.value.status_code == 400
    assert "common" in exc.value.detail


def test_change_password_schema_matches_the_length_rule():
    # The schema is only an early 422; the bounds are the policy's.
    with pytest.raises(ValidationError):
        PasswordChangeRequest(current_password=CURRENT, new_password="x" * 11)
    with pytest.raises(ValidationError):
        PasswordChangeRequest(current_password=CURRENT, new_password="x" * 129)
    PasswordChangeRequest(current_password=CURRENT, new_password="x" * 12)
