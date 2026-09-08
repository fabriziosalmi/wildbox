"""
Tests for the shared gateway authentication dependency.

open_security_shared has no tests of its own, and it holds gateway_auth (the
dependency four services use to verify the proof-of-origin secret and the
injected identity headers) and tenancy (which decides what rows a caller sees).
A change to either alters the trust or tenancy boundary of several services at
once, and the only thing that would have caught it was a handful of integration
tests needing the full stack up (WILDBO-TEST-03).

These are pure-function tests; they need no stack.
"""

import pytest
from fastapi import HTTPException
from open_security_shared.gateway_auth import (
    GatewayUser,
    get_user_from_gateway_headers,
)

SECRET = "test-gateway-secret-at-least-32-characters"
# GatewayUser declares these as UUID4, so the fixtures must be version-4 UUIDs;
# the gateway only ever injects ids that identity generated with uuid4().
USER_ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
TEAM_ID = "9c858901-8a57-4791-81fe-4c455b099bc9"


@pytest.fixture(autouse=True)
def _configured_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)


async def _call(**overrides):
    kwargs = {
        "x_wildbox_user_id": USER_ID,
        "x_wildbox_team_id": TEAM_ID,
        "x_wildbox_role": "member",
        "x_gateway_secret": SECRET,
    }
    kwargs.update(overrides)
    return await get_user_from_gateway_headers(**kwargs)


@pytest.mark.asyncio
async def test_valid_gateway_headers_yield_a_user():
    user = await _call()
    assert isinstance(user, GatewayUser)
    assert str(user.user_id) == USER_ID
    assert str(user.team_id) == TEAM_ID


@pytest.mark.asyncio
async def test_wrong_proof_of_origin_secret_is_rejected():
    """A forged X-Wildbox-* header set must not authenticate."""
    with pytest.raises(HTTPException) as exc:
        await _call(x_gateway_secret="not-the-secret")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_missing_proof_of_origin_secret_is_rejected():
    with pytest.raises(HTTPException) as exc:
        await _call(x_gateway_secret=None)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_unconfigured_secret_fails_closed(monkeypatch):
    """
    With no secret configured the service must refuse everything rather than
    trust forgeable headers. This is the fail-closed property the services'
    comments describe; nothing tested it.
    """
    monkeypatch.delenv("GATEWAY_INTERNAL_SECRET", raising=False)
    with pytest.raises(HTTPException) as exc:
        await _call()
    assert exc.value.status_code in (403, 503)


@pytest.mark.asyncio
async def test_missing_identity_headers_are_rejected():
    with pytest.raises(HTTPException):
        await _call(x_wildbox_user_id=None)
    with pytest.raises(HTTPException):
        await _call(x_wildbox_team_id=None)
