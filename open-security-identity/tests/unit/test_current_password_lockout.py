"""A signed-in session cannot guess the password without limit (#569).

Changing the password, deleting the account and the profile update ask for
the current password. A wrong one answered 400 and counted nothing, so a
session -- a stolen token is enough -- could be used to guess the password
for as long as it lived, whatever the login lockout (#509) said. These pin
that a wrong current password counts towards the same per-account counter as
a failed login, and that a locked account is refused like a locked login.

The Redis helpers are replaced by an in-memory counter that follows the same
rules, and the database by a stub, so this needs neither.
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
from app.config import settings  # noqa: E402
from app.schemas import AccountDeletionRequest  # noqa: E402
from app.schemas import PasswordChangeRequest, UserProfileUpdate  # noqa: E402
from fastapi import HTTPException  # noqa: E402

PASSWORD = "correct horse battery staple"
HASH = get_password_hash(PASSWORD)
LIMIT = settings.max_failed_login_attempts


def make_user(email="Alice@Example.com"):
    return SimpleNamespace(
        id=uuid.uuid4(), email=email, hashed_password=HASH, is_active=True
    )


class FakeSession:
    """Enough of an AsyncSession for the self-service routes' refusals."""

    def __init__(self):
        self.commits = 0

    async def commit(self):
        self.commits += 1

    async def refresh(self, _obj):
        return None

    async def execute(self, _query):
        raise AssertionError("a refused request must not reach the database")


@pytest.fixture
def counter(monkeypatch):
    attempts = {}

    async def record(email):
        attempts[email] = attempts.get(email, 0) + 1
        return attempts[email]

    async def clear(email):
        attempts.pop(email, None)

    async def locked(email):
        return attempts.get(email, 0) >= LIMIT

    monkeypatch.setattr(user_manager, "record_failed_login", record)
    monkeypatch.setattr(user_manager, "clear_failed_logins", clear)
    monkeypatch.setattr(user_manager, "is_account_locked", locked)
    return attempts


def run(coro):
    return asyncio.run(coro)


def status_of(coro):
    with pytest.raises(HTTPException) as exc:
        run(coro)
    return exc.value


# -- the check itself ---------------------------------------------------------


def test_a_wrong_current_password_counts_like_a_failed_login(counter):
    user = make_user()
    error = status_of(user_manager.verify_current_password(user, "wrong"))
    assert error.status_code == 400
    # The login counter's key: the normalised email.
    assert counter == {"alice@example.com": 1}


def test_a_missing_current_password_counts_too(counter):
    user = make_user()
    assert (
        status_of(user_manager.verify_current_password(user, None)).status_code == 400
    )
    assert counter == {"alice@example.com": 1}


def test_the_lock_refuses_even_the_right_password_like_the_login(counter):
    user = make_user()
    for _ in range(LIMIT):
        status_of(user_manager.verify_current_password(user, "wrong"))

    error = status_of(user_manager.verify_current_password(user, PASSWORD))
    assert error.status_code == 429
    assert error.detail == user_manager.account_locked_error().detail
    assert error.headers["Retry-After"] == str(settings.account_lockout_minutes * 60)


def test_failed_logins_and_wrong_current_passwords_share_one_counter(counter):
    """A lock reached by failed logins also stops the session's checks."""
    user = make_user()
    counter["alice@example.com"] = LIMIT
    assert (
        status_of(user_manager.verify_current_password(user, PASSWORD)).status_code
        == 429
    )


def test_the_right_password_clears_the_counter(counter):
    user = make_user()
    for _ in range(LIMIT - 1):
        status_of(user_manager.verify_current_password(user, "wrong"))
    run(user_manager.verify_current_password(user, PASSWORD))
    assert counter == {}


# -- the routes that ask for it -----------------------------------------------


def change_password(user, current):
    return users.change_my_password(
        PasswordChangeRequest(current_password=current, new_password="n" * 16),
        current_user=user,
        db=FakeSession(),
    )


def delete_account(user, password):
    return users.delete_my_account(
        AccountDeletionRequest(password=password, confirm_deletion=True),
        current_user=user,
        db=FakeSession(),
    )


def profile_password(user, current):
    return users.update_my_profile(
        UserProfileUpdate(current_password=current, new_password="n" * 16),
        current_user=user,
        db=FakeSession(),
    )


@pytest.mark.parametrize(
    "call",
    [change_password, delete_account, profile_password],
    ids=["change-password", "delete-account", "profile"],
)
def test_each_route_counts_and_locks(counter, call):
    user = make_user()
    for _ in range(LIMIT):
        assert status_of(call(user, "wrong")).status_code == 400
    assert counter == {"alice@example.com": LIMIT}

    # Locked: the right password is refused too, so guessing gains nothing.
    assert status_of(call(user, PASSWORD)).status_code == 429


def test_change_password_keeps_its_message(counter):
    error = status_of(change_password(make_user(), "wrong"))
    assert error.detail == "Incorrect current password"


def test_delete_account_keeps_its_message(counter):
    error = status_of(delete_account(make_user(), "wrong"))
    assert error.detail == "Incorrect password"
