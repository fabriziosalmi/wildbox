"""Unit tests for #175: internal tool calls forward the caller's gateway
identity (X-Wildbox-* + secret) instead of a static god-mode key, with a safe
fallback to the (now non-privileged) service key.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.tools.wildbox_client import (  # noqa: E402
    WildboxAPIClient,
    set_caller_identity,
    _caller_identity,
)


@pytest.fixture
def client():
    c = WildboxAPIClient()
    c.api_key = "SERVICE-KEY"
    c.gateway_secret = "GW-SECRET"
    _caller_identity.set(None)
    yield c
    _caller_identity.set(None)


def test_falls_back_to_service_key_without_caller(client):
    headers = client._request_headers()
    assert headers["X-API-Key"] == "SERVICE-KEY"
    assert "X-Wildbox-User-ID" not in headers
    assert "X-Gateway-Secret" not in headers


def test_forwards_caller_gateway_identity(client):
    set_caller_identity("user-1", "team-1", "admin")
    headers = client._request_headers()
    assert headers["X-Wildbox-User-ID"] == "user-1"
    assert headers["X-Wildbox-Team-ID"] == "team-1"
    assert headers["X-Wildbox-Role"] == "admin"
    assert headers["X-Gateway-Secret"] == "GW-SECRET"
    # The static key is NOT sent when forwarding real identity.
    assert "X-API-Key" not in headers


def test_falls_back_when_secret_missing(client):
    # A caller identity without a configured secret can't prove gateway origin,
    # so we must not send unverified X-Wildbox-* headers — fall back to the key.
    client.gateway_secret = ""
    set_caller_identity("user-1", "team-1", "member")
    headers = client._request_headers()
    assert headers["X-API-Key"] == "SERVICE-KEY"
    assert "X-Wildbox-User-ID" not in headers
