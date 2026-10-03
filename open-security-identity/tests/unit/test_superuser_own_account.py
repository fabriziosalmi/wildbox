"""A superuser's own account follows the self-service rules (#569).

PATCH /api/v1/users/{id} (the gateway's /auth/users/{id}) is the
superuser's update and calls UserManager.update() with safe=False, which
applies a `password` without the current one. Pointed at the caller's own id
it was a way round what PATCH /users/me refuses (#559): a superuser's session
could change its own password, or its email, without knowing the password.
Other accounts are still reset as before. The parent update is a recorder
and the tokens are real ones, so this needs neither a database nor Redis.
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
from fastapi import HTTPException  # noqa: E402
from fastapi_users import BaseUserManager, exceptions  # noqa: E402

ADMIN = SimpleNamespace(id=uuid.uuid4(), email="root@example.com")
OTHER = SimpleNamespace(id=uuid.uuid4(), email="bob@example.com")


def run(coro):
    return asyncio.run(coro)


def request_from(user=None, authorization=None):
    if authorization is None and user is not None:
        token = run(user_manager.get_jwt_strategy().write_token(user))
        authorization = f"Bearer {token}"
    headers = {"authorization": authorization} if authorization else {}
    return SimpleNamespace(headers=headers)


@pytest.fixture
def parent_calls(monkeypatch):
    calls = []

    async def parent_update(self, user_update, user, safe=False, request=None):
        calls.append({"update": user_update, "user": user, "safe": safe})
        return user

    monkeypatch.setattr(BaseUserManager, "update", parent_update)
    return calls


def superuser_update(user_update, target, request):
    manager = user_manager.UserManager(user_db=None)
    return run(manager.update(user_update, target, safe=False, request=request))


def test_a_superuser_cannot_set_their_own_password_by_id(parent_calls):
    with pytest.raises(exceptions.InvalidPasswordException) as exc:
        superuser_update(
            UserUpdate(password="a-brand-new-password"), ADMIN, request_from(ADMIN)
        )
    assert "change-password" in exc.value.reason
    assert parent_calls == []


def test_a_superuser_needs_the_password_to_move_their_own_email(parent_calls):
    with pytest.raises(HTTPException) as exc:
        superuser_update(
            UserUpdate(email="elsewhere@example.com"), ADMIN, request_from(ADMIN)
        )
    assert exc.value.status_code == 400
    assert parent_calls == []


def test_a_superuser_still_resets_another_accounts_password(parent_calls):
    assert (
        superuser_update(
            UserUpdate(password="an-admin-reset-pass"), OTHER, request_from(ADMIN)
        )
        is OTHER
    )
    (call,) = parent_calls
    assert call["safe"] is False
    assert call["update"].password == "an-admin-reset-pass"


def test_a_superuser_still_changes_their_own_flags_by_id(parent_calls):
    """Only the password and the email need re-authentication."""
    update = UserUpdate(is_verified=True)
    assert superuser_update(update, ADMIN, request_from(ADMIN)) is ADMIN
    assert len(parent_calls) == 1


@pytest.mark.parametrize(
    "authorization", [None, "Basic cm9vdDpyb290", "Bearer not-a-jwt"]
)
def test_without_a_readable_bearer_the_target_is_not_the_caller(
    parent_calls, authorization
):
    """The route authenticated the caller; this only decides own vs other."""
    request = request_from(authorization=authorization)
    assert superuser_update(UserUpdate(password="pw-" * 6), OTHER, request) is OTHER
