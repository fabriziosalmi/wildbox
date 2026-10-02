"""Unit tests for RevocableJWTStrategy (app/user_manager.py).

The login endpoint's tokens used to carry only sub, aud and exp: logout could
not revoke them (no jti) and two logins in the same second produced the same
token. These tests pin the three properties the fix provides, without a
database or Redis: the blacklist lookup and the revocation are patched.
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
from app.auth import verify_access_token  # noqa: E402

USER = SimpleNamespace(id=uuid.uuid4())


class FakeUserManager:
    """Just enough of BaseUserManager for JWTStrategy.read_token()."""

    def parse_id(self, value):
        return uuid.UUID(value)

    async def get(self, user_id):
        assert user_id == USER.id
        return USER


def run(coro):
    return asyncio.run(coro)


def strategy():
    return user_manager.get_jwt_strategy()


def test_login_tokens_carry_a_jti_and_an_iat():
    token = run(strategy().write_token(USER))
    payload = verify_access_token(token)
    assert payload["sub"] == str(USER.id)
    assert payload["jti"]
    assert payload["iat"] <= payload["exp"]


def test_two_tokens_for_the_same_user_in_the_same_second_differ():
    s = strategy()
    first, second = run(s.write_token(USER)), run(s.write_token(USER))
    assert first != second
    assert verify_access_token(first)["jti"] != verify_access_token(second)["jti"]


def test_a_live_token_still_reads_as_its_user(monkeypatch):
    async def not_revoked(jti):
        return False

    monkeypatch.setattr(user_manager, "is_token_blacklisted", not_revoked)
    token = run(strategy().write_token(USER))
    assert run(strategy().read_token(token, FakeUserManager())) is USER


def test_a_revoked_token_reads_as_nobody(monkeypatch):
    seen = []

    async def revoked(jti):
        seen.append(jti)
        return True

    monkeypatch.setattr(user_manager, "is_token_blacklisted", revoked)
    token = run(strategy().write_token(USER))
    assert run(strategy().read_token(token, FakeUserManager())) is None
    assert seen == [verify_access_token(token)["jti"]]


def test_a_garbage_token_reads_as_nobody():
    assert run(strategy().read_token("not-a-jwt", FakeUserManager())) is None
    assert run(strategy().read_token(None, FakeUserManager())) is None


def test_destroy_token_revokes(monkeypatch):
    revoked = []

    async def fake_revoke(token):
        revoked.append(token)

    monkeypatch.setattr(user_manager, "revoke_token", fake_revoke)
    token = run(strategy().write_token(USER))
    run(strategy().destroy_token(token, USER))
    assert revoked == [token]


@pytest.mark.parametrize("missing", ["jti"])
def test_revoke_refuses_a_token_without_jti(missing):
    """Tokens minted before this change have no jti; revoking one must say so
    rather than pretend it worked."""
    import jwt
    from app import logout
    from app.config import settings
    from fastapi import HTTPException

    token = jwt.encode(
        {"sub": str(USER.id), "aud": ["fastapi-users:auth"], "exp": 4102444800},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(HTTPException) as exc:
        run(logout.revoke_token(token))
    assert exc.value.status_code == 400
