"""A signed-in user cannot change their password without the current one (#559).

fastapi-users' PATCH /users/me calls UserManager.update(..., safe=True) and
applied a `password` field without asking for the current password, so a
stolen session token was enough to take the account over. The parent update
is replaced by a recorder here, so this needs neither a database nor Redis.
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
from app.schemas import UserUpdate  # noqa: E402
from fastapi_users import BaseUserManager, exceptions  # noqa: E402

USER = SimpleNamespace(id=uuid.uuid4(), email="alice@example.com")


@pytest.fixture
def parent_calls(monkeypatch):
    calls = []

    async def parent_update(self, user_update, user, safe=False, request=None):
        calls.append({"update": user_update, "safe": safe})
        return user

    monkeypatch.setattr(BaseUserManager, "update", parent_update)
    return calls


def _update(user_update, safe):
    manager = user_manager.UserManager(user_db=None)
    return asyncio.run(manager.update(user_update, USER, safe=safe))


def test_self_service_update_refuses_a_password(parent_calls):
    with pytest.raises(exceptions.InvalidPasswordException) as exc:
        _update(UserUpdate(password="a-brand-new-password"), safe=True)

    assert "change-password" in exc.value.reason
    assert parent_calls == [], "the password must not reach the database"


def test_self_service_update_refuses_a_password_sent_with_an_email(parent_calls):
    with pytest.raises(exceptions.InvalidPasswordException):
        _update(
            UserUpdate(email="bob@example.com", password="a-brand-new-password"),
            safe=True,
        )
    assert parent_calls == []


def test_self_service_update_still_changes_the_email(parent_calls):
    assert _update(UserUpdate(email="bob@example.com"), safe=True) is USER
    assert len(parent_calls) == 1
    assert parent_calls[0]["safe"] is True
    assert parent_calls[0]["update"].email == "bob@example.com"


def test_superuser_update_can_still_reset_a_password(parent_calls):
    """PATCH /users/{id} is an administrator's reset (safe=False)."""
    assert _update(UserUpdate(password="an-admin-reset-pass"), safe=False) is USER
    assert len(parent_calls) == 1
    assert parent_calls[0]["safe"] is False
