"""Per-account lockout on password login (#509).

The helpers in token_blacklist.py are replaced by an in-memory counter that
follows the same rules (lock once the count reaches the threshold), and the
parent authenticate() by a stub, so this needs neither Redis nor a database.
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
from app.config import settings  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi_users import BaseUserManager  # noqa: E402

USER = SimpleNamespace(id=uuid.uuid4(), email="alice@example.com")
PASSWORD = "correct horse battery staple"


@pytest.fixture
def counter(monkeypatch):
    attempts = {}

    async def record(email):
        attempts[email] = attempts.get(email, 0) + 1
        return attempts[email]

    async def clear(email):
        attempts.pop(email, None)

    async def locked(email):
        return attempts.get(email, 0) >= settings.max_failed_login_attempts

    async def parent_authenticate(self, credentials):
        if credentials.username == USER.email and credentials.password == PASSWORD:
            return USER
        return None

    monkeypatch.setattr(user_manager, "record_failed_login", record)
    monkeypatch.setattr(user_manager, "clear_failed_logins", clear)
    monkeypatch.setattr(user_manager, "is_account_locked", locked)
    monkeypatch.setattr(BaseUserManager, "authenticate", parent_authenticate)
    return attempts


def _login(email, password):
    manager = user_manager.UserManager(user_db=None)
    credentials = SimpleNamespace(username=email, password=password)
    return asyncio.run(manager.authenticate(credentials))


def _fail(email, times):
    for _ in range(times):
        assert _login(email, "wrong") is None


def test_correct_password_logs_in(counter):
    assert _login(USER.email, PASSWORD) is USER


def test_account_is_locked_after_the_threshold_even_with_the_right_password(counter):
    _fail(USER.email, settings.max_failed_login_attempts)
    with pytest.raises(HTTPException) as exc:
        _login(USER.email, PASSWORD)
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == str(
        settings.account_lockout_minutes * 60
    )


def test_below_the_threshold_the_right_password_still_works(counter):
    _fail(USER.email, settings.max_failed_login_attempts - 1)
    assert _login(USER.email, PASSWORD) is USER


def test_a_successful_login_clears_the_counter(counter):
    _fail(USER.email, settings.max_failed_login_attempts - 1)
    assert _login(USER.email, PASSWORD) is USER
    _fail(USER.email, settings.max_failed_login_attempts - 1)
    assert _login(USER.email, PASSWORD) is USER


def test_unknown_accounts_lock_the_same_way(counter):
    """The 429 must not reveal whether an email is registered."""
    ghost = "nobody@example.com"
    _fail(ghost, settings.max_failed_login_attempts)
    with pytest.raises(HTTPException) as exc:
        _login(ghost, "anything")
    assert exc.value.status_code == 429


def test_email_case_and_spaces_do_not_reset_the_counter(counter):
    _fail(" Alice@Example.COM ", settings.max_failed_login_attempts)
    with pytest.raises(HTTPException):
        _login(USER.email, PASSWORD)
