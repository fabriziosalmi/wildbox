"""Unit tests for fail-closed revocation (app/logout.py, app/gateway_cache.py).

Logout used to blacklist the jti -- swallowing a Redis error -- and then purge
the gateway's cache best-effort, so it could answer success while the gateway
went on serving the token (#571). These tests pin the contract that replaced
it: revoke_jtis() returns only when the gateway has confirmed every jti AND
the blacklist is written, and logout turns anything less into a 503. No Redis
and no gateway: both are patched, the gateway at the HTTP transport.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import gateway_cache, logout, user_manager  # noqa: E402
from fastapi import HTTPException  # noqa: E402

SECRET = "unit-test-gateway-proof-of-origin"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def gateway(monkeypatch):
    """A scripted gateway: each call pops the next response (or exception)."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(gateway_cache, "_RETRY_DELAYS", (0, 0))
    state = {"script": [], "requests": []}

    def handler(request):
        state["requests"].append(request)
        outcome = state["script"].pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    real_client = httpx.AsyncClient

    def client(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(gateway_cache.httpx, "AsyncClient", client)
    return state


@pytest.fixture
def blacklist(monkeypatch):
    written = {}

    async def blacklist_token(jti, expires_at):
        written[jti] = expires_at

    monkeypatch.setattr(logout, "blacklist_token", blacklist_token)
    return written


def confirmed(n):
    return httpx.Response(200, json={"purged": True, "scope": "jtis", "revoked": n})


def sessions(*jtis, minutes=30):
    expires = datetime.utcnow() + timedelta(minutes=minutes)
    return {jti: expires for jti in jtis}


def test_revoke_jtis_blacklists_then_has_the_gateway_refuse_them(gateway, blacklist):
    gateway["script"] = [confirmed(2)]
    run(logout.revoke_jtis(sessions("a", "b")))

    assert set(blacklist) == {"a", "b"}
    (request,) = gateway["requests"]
    assert request.headers["X-Gateway-Secret"] == SECRET
    body = httpx.Response(200, content=request.content).json()
    assert body["jtis"] == ["a", "b"]
    # The marker must last as long as the tokens could.
    assert 1700 < body["ttl"] <= 1800


def test_a_lost_purge_is_retried(gateway, blacklist):
    gateway["script"] = [
        httpx.ConnectError("refused"),
        httpx.Response(502),
        confirmed(1),
    ]
    run(logout.revoke_jtis(sessions("a")))
    assert len(gateway["requests"]) == 3


def test_an_unconfirmed_purge_fails_the_revocation(gateway, blacklist):
    gateway["script"] = [httpx.ReadTimeout("slow")] * 3
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_jtis(sessions("a")))
    assert len(gateway["requests"]) == 3
    # Nothing written: the session is still whole, so the logout can be
    # retried (a blacklisted token could no longer call /auth/jwt/logout).
    assert blacklist == {}


def test_a_gateway_that_does_not_count_the_jtis_is_not_trusted(gateway, blacklist):
    """A gateway without revocation markers answers 200 to any purge (it flushes
    its cache) but cannot refuse a decision that was in flight. Not enough."""
    gateway["script"] = [httpx.Response(200, json={"purged": True, "scope": "all"})] * 3
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_jtis(sessions("a")))


def test_no_gateway_secret_fails_the_revocation(gateway, blacklist, monkeypatch):
    monkeypatch.delenv("GATEWAY_INTERNAL_SECRET")
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_jtis(sessions("a")))
    assert gateway["requests"] == [] and blacklist == {}


def test_a_blacklist_failure_fails_the_revocation(gateway, monkeypatch):
    async def redis_down(jti, expires_at):
        raise ConnectionError("redis down")

    monkeypatch.setattr(logout, "blacklist_token", redis_down)
    gateway["script"] = [confirmed(1)]
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_jtis(sessions("a")))
    assert len(gateway["requests"]) == 1


def test_nothing_to_revoke_is_a_no_op(gateway, blacklist):
    run(logout.revoke_jtis({}))
    assert gateway["requests"] == [] and blacklist == {}


def _login_token():
    user = type("U", (), {"id": uuid.uuid4()})()
    return run(user_manager.get_jwt_strategy().write_token(user))


def test_logout_revokes_the_token_s_jti(gateway, blacklist):
    gateway["script"] = [confirmed(1)]
    token = _login_token()
    run(logout.revoke_token(token))
    assert list(blacklist) == [logout.verify_access_token(token)["jti"]]


def test_logout_answers_503_when_the_revocation_is_not_confirmed(gateway, blacklist):
    """Never 2xx while the gateway may still accept the token; logout is
    idempotent, so the client can repeat it."""
    gateway["script"] = [httpx.Response(503)] * 3
    with pytest.raises(HTTPException) as exc:
        run(logout.revoke_token(_login_token()))
    assert exc.value.status_code == 503


def test_blacklist_token_no_longer_swallows_a_redis_error(monkeypatch):
    from app import token_blacklist

    class DownRedis:
        async def setex(self, *args):
            raise ConnectionError("redis down")

    async def get_redis():
        return DownRedis()

    monkeypatch.setattr(token_blacklist, "get_redis", get_redis)
    with pytest.raises(ConnectionError):
        run(
            token_blacklist.blacklist_token(
                "a", datetime.utcnow() + timedelta(minutes=1)
            )
        )


def test_an_unparsable_answer_is_logged_with_its_status_and_start(
    gateway, blacklist, caplog
):
    """The gateway once answered '{...}nil'; the log said only JSONDecodeError."""
    body = b'{"purged":true,"revoked":1,"scope":"jtis"}nil\n'
    gateway["script"] = [httpx.Response(200, content=body)] * 3
    with caplog.at_level("WARNING", logger="app.gateway_cache"):
        with pytest.raises(logout.RevocationError):
            run(logout.revoke_jtis(sessions("a")))
    assert "HTTP 200 with a body that is not JSON" in caplog.text
    assert '"revoked":1,"scope":"jtis"}nil' in caplog.text
    assert SECRET not in caplog.text
