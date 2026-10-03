"""Changing the account's email needs the current password (#569).

With a session alone, PATCH /auth/users/me (fastapi-users, safe=True) and
PATCH /api/v1/admin/me/profile both moved the account to another address,
after which forgot-password sends the reset link there: a stolen token was
enough to take the account over. The parent update, the lockout counter and
the database are stubs here, so this needs neither Redis nor PostgreSQL.
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

from app import user_manager  # noqa: E402
from app.api_v1.endpoints import users  # noqa: E402
from app.auth import get_password_hash  # noqa: E402
from app.schemas import UserProfileUpdate, UserUpdate  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi_users import BaseUserManager, exceptions  # noqa: E402
from fastapi_users.jwt import decode_jwt  # noqa: E402

PASSWORD = "correct horse battery staple"
HASH = get_password_hash(PASSWORD)
NEW_EMAIL = "mallory@example.com"


def make_user():
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="alice@example.com",
        hashed_password=HASH,
        is_active=True,
        is_verified=True,
    )


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def counter(monkeypatch):
    attempts = {}

    async def record(email):
        attempts[email] = attempts.get(email, 0) + 1
        return attempts[email]

    async def clear(email):
        attempts.pop(email, None)

    async def locked(email):
        return False

    monkeypatch.setattr(user_manager, "record_failed_login", record)
    monkeypatch.setattr(user_manager, "clear_failed_logins", clear)
    monkeypatch.setattr(user_manager, "is_account_locked", locked)
    return attempts


@pytest.fixture
def parent_calls(monkeypatch):
    calls = []

    async def parent_update(self, user_update, user, safe=False, request=None):
        calls.append({"update": user_update, "safe": safe})
        return user

    monkeypatch.setattr(BaseUserManager, "update", parent_update)
    return calls


def update(user_update, user, safe=True):
    manager = user_manager.UserManager(user_db=None)
    return run(manager.update(user_update, user, safe=safe))


# -- PATCH /auth/users/me ------------------------------------------------------


def test_patch_me_refuses_an_email_change_without_the_current_password(
    counter, parent_calls
):
    with pytest.raises(HTTPException) as exc:
        update(UserUpdate(email=NEW_EMAIL), make_user())
    assert exc.value.status_code == 400
    assert "current password" in exc.value.detail
    assert parent_calls == [], "the email must not reach the database"
    # Not a guess: a request that did not send a password is not counted.
    assert counter == {}


def test_patch_me_refuses_an_email_change_with_a_wrong_password(counter, parent_calls):
    with pytest.raises(HTTPException) as exc:
        update(UserUpdate(email=NEW_EMAIL, current_password="wrong"), make_user())
    assert exc.value.status_code == 400
    assert parent_calls == []
    assert counter == {"alice@example.com": 1}


def test_patch_me_changes_the_email_with_the_current_password(counter, parent_calls):
    user = make_user()
    assert update(UserUpdate(email=NEW_EMAIL, current_password=PASSWORD), user) is user
    (call,) = parent_calls
    assert call["safe"] is True
    # The password is a check, never a field to write.
    assert call["update"].create_update_dict() == {"email": NEW_EMAIL}


def test_patch_me_needs_no_password_when_the_email_does_not_change(
    counter, parent_calls
):
    user = make_user()
    assert update(UserUpdate(email=user.email), user) is user
    assert len(parent_calls) == 1


def test_superuser_update_of_another_account_needs_no_password(counter, parent_calls):
    """PATCH /users/{id} (safe=False) is an administrator's change."""
    user = make_user()
    assert update(UserUpdate(email=NEW_EMAIL), user, safe=False) is user
    assert parent_calls[0]["update"].create_update_dict_superuser() == {
        "email": NEW_EMAIL
    }


# -- PATCH /api/v1/admin/me/profile ------------------------------------------


class FakeSession:
    def __init__(self):
        self.commits = 0

    async def execute(self, _query):
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def commit(self):
        self.commits += 1

    async def refresh(self, _obj):
        return None


def profile(user, **fields):
    db = FakeSession()
    result = run(
        users.update_my_profile(UserProfileUpdate(**fields), current_user=user, db=db)
    )
    return result, db


def test_profile_refuses_an_email_change_without_the_current_password(counter):
    user = make_user()
    with pytest.raises(HTTPException) as exc:
        profile(user, email=NEW_EMAIL)
    assert exc.value.status_code == 400
    assert user.email == "alice@example.com"


def test_profile_refuses_an_email_change_with_a_wrong_password(counter):
    user = make_user()
    with pytest.raises(HTTPException) as exc:
        profile(user, email=NEW_EMAIL, current_password="wrong")
    assert exc.value.status_code == 400
    assert user.email == "alice@example.com"
    assert counter == {"alice@example.com": 1}


def test_profile_changes_the_email_with_the_current_password(counter):
    user = make_user()
    result, db = profile(user, email=NEW_EMAIL, current_password=PASSWORD)
    assert result.email == NEW_EMAIL
    assert result.is_verified is False
    assert db.commits == 1


# -- password-reset tokens -----------------------------------------------------


class ResetUserDb:
    def __init__(self, user):
        self.user = user

    async def get(self, user_id):
        return self.user if user_id == self.user.id else None


def issue_reset_token(manager, user):
    tokens = []

    async def capture(self, user, token, request=None):
        tokens.append(token)

    manager.on_after_forgot_password = capture.__get__(manager)
    run(manager.forgot_password(user))
    return tokens[0]


def test_reset_tokens_carry_the_email():
    user = make_user()
    manager = user_manager.UserManager(ResetUserDb(user))
    token = issue_reset_token(manager, user)
    data = decode_jwt(
        token,
        manager.reset_password_token_secret,
        [manager.reset_password_token_audience],
    )
    assert data["email"] == user.email


def test_an_email_change_invalidates_reset_tokens(monkeypatch):
    user = make_user()
    manager = user_manager.UserManager(ResetUserDb(user))
    token = issue_reset_token(manager, user)
    user.email = NEW_EMAIL

    async def must_not_run(self, token, password, request=None):
        raise AssertionError("the parent reset must not run")

    monkeypatch.setattr(BaseUserManager, "reset_password", must_not_run)
    with pytest.raises(exceptions.InvalidResetPasswordToken):
        run(manager.reset_password(token, "a-brand-new-password"))


def test_a_reset_token_for_the_current_email_is_passed_on(monkeypatch):
    user = make_user()
    manager = user_manager.UserManager(ResetUserDb(user))
    token = issue_reset_token(manager, user)
    passed = []

    async def parent_reset(self, token, password, request=None):
        passed.append(token)
        return user

    monkeypatch.setattr(BaseUserManager, "reset_password", parent_reset)
    assert run(manager.reset_password(token, "a-brand-new-password")) is user
    assert passed == [token]
