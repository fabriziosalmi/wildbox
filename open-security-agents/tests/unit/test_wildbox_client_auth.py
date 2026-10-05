"""Internal tool calls forward the caller's gateway identity (#175), and
nothing else (#567).

The client used to fall back to the static INTERNAL_API_KEY as X-API-Key when
it had no caller identity or no gateway secret. The tools service has not
accepted that key since #566 and answers 401, so the call now fails before it
is sent, with a message that says what is missing.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.tools.wildbox_client import (  # noqa: E402
    CallerIdentityUnavailable,
    WildboxAPIClient,
    _caller_identity,
    set_caller_identity,
)


@pytest.fixture
def client():
    c = WildboxAPIClient()
    c.gateway_secret = "GW-SECRET"
    _caller_identity.set(None)
    yield c
    _caller_identity.set(None)


def test_forwards_caller_gateway_identity(client):
    set_caller_identity("user-1", "team-1", "admin")
    headers = client._request_headers()
    assert headers["X-Wildbox-User-ID"] == "user-1"
    assert headers["X-Wildbox-Team-ID"] == "team-1"
    assert headers["X-Wildbox-Role"] == "admin"
    assert headers["X-Gateway-Secret"] == "GW-SECRET"
    assert "X-API-Key" not in headers
    # A service acting for the caller, said so: tools and data refuse a
    # request that needs a scope and does not state its credential (#637).
    assert headers["X-Wildbox-Auth-Type"] == "service"
    assert "X-Wildbox-Scopes" not in headers


def test_without_a_caller_the_call_fails_and_says_why(client):
    with pytest.raises(CallerIdentityUnavailable, match="no caller identity"):
        client._request_headers()


def test_without_the_secret_the_call_fails_and_says_why(client):
    # A caller identity without the secret cannot prove gateway origin, so the
    # X-Wildbox-* headers must not be sent unverified either.
    client.gateway_secret = ""
    set_caller_identity("user-1", "team-1", "member")
    with pytest.raises(CallerIdentityUnavailable, match="GATEWAY_INTERNAL_SECRET"):
        client._request_headers()


def test_with_neither_both_are_named(client):
    client.gateway_secret = ""
    with pytest.raises(CallerIdentityUnavailable) as raised:
        client._request_headers()
    assert "no caller identity" in str(raised.value)
    assert "GATEWAY_INTERNAL_SECRET" in str(raised.value)


def test_a_tool_call_without_identity_sends_nothing(client, monkeypatch):
    """The failure happens before any request, and reaches the caller."""
    import httpx

    sent = []

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, **kwargs):
            sent.append(url)
            raise AssertionError("no request may be sent")

    monkeypatch.setattr(httpx, "AsyncClient", RecordingClient)

    with pytest.raises(CallerIdentityUnavailable):
        asyncio.run(client.run_tool("whois_lookup", {"target": "example.com"}))
    assert sent == []


def test_the_client_has_no_service_key(client):
    assert not hasattr(client, "api_key")
