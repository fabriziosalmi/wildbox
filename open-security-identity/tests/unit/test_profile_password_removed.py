"""PATCH /api/v1/admin/me/profile no longer sets a password (#569).

It set any new password -- no length rule (change-password requires 12),
hashed directly, bypassing UserManager -- as a second, weaker way to do what
change-password does. Nothing used it: the dashboard calls change-password.
A request carrying new_password is now refused, with or without the right
current password, and nothing is written.
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

from app.api_v1.endpoints import users  # noqa: E402
from app.auth import get_password_hash  # noqa: E402
from app.schemas import UserProfileUpdate  # noqa: E402
from fastapi import HTTPException  # noqa: E402

PASSWORD = "correct horse battery staple"
HASH = get_password_hash(PASSWORD)


class UntouchableSession:
    async def execute(self, _query):
        raise AssertionError("a refused request must not reach the database")

    async def commit(self):
        raise AssertionError("a refused request must not write")

    async def refresh(self, _obj):
        raise AssertionError("a refused request must not write")


def make_user():
    return SimpleNamespace(
        id=uuid.uuid4(), email="alice@example.com", hashed_password=HASH
    )


def profile(user, route, **fields):
    return asyncio.run(
        route(UserProfileUpdate(**fields), current_user=user, db=UntouchableSession())
    )


@pytest.mark.parametrize(
    "route",
    [users.update_my_profile, users.update_my_profile_put],
    ids=["PATCH /me/profile", "PUT /me"],
)
@pytest.mark.parametrize(
    "fields",
    [
        {"current_password": PASSWORD, "new_password": "short"},
        {"current_password": PASSWORD, "new_password": "a-long-enough-password"},
        {"new_password": "a-long-enough-password"},
    ],
    ids=["short", "long", "without-current"],
)
def test_profile_refuses_to_set_a_password(route, fields):
    user = make_user()
    with pytest.raises(HTTPException) as exc:
        profile(user, route, **fields)
    assert exc.value.status_code == 400
    assert "change-password" in exc.value.detail
    assert user.hashed_password == HASH
