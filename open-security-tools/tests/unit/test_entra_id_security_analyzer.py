"""Unit tests for the Entra ID Security Analyzer tool.

Mocks the Microsoft Graph HTTP calls (token endpoint, /users with
signInActivity, and /reports/authenticationMethods/userRegistrationDetails)
so the tests run without real Entra ID credentials or network access.
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "entra_id_security_analyzer"

sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(TOOL_DIR))

import main as entra_main  # noqa: E402
from schemas import EntraIDSecurityAnalyzerInput  # noqa: E402


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    async def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self, post_response, get_responses):
        self._post_response = post_response
        self._get_responses = list(get_responses)
        self._get_call_count = 0

    def post(self, url, data=None, ssl=None):
        return self._post_response

    def get(self, url, headers=None, ssl=None):
        response = self._get_responses[self._get_call_count]
        self._get_call_count += 1
        return response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _stale_iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_missing_credentials_returns_failure():
    for var in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"):
        os.environ.pop(var, None)

    data = EntraIDSecurityAnalyzerInput()
    result = asyncio.run(entra_main.execute_tool(data))

    assert result.success is False
    assert "credentials" in result.error_message.lower()


def test_execute_tool_flags_stale_accounts_and_mfa_gaps(monkeypatch):
    token_response = FakeResponse(200, {"access_token": "fake-token"})

    users_payload = {
        "value": [
            {
                "userPrincipalName": "alice@contoso.com",
                "displayName": "Alice",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": _stale_iso(400)},
            },
            {
                "userPrincipalName": "bob@contoso.com",
                "displayName": "Bob",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": _stale_iso(5)},
            },
        ]
    }
    registration_payload = {
        "value": [
            {
                "userPrincipalName": "alice@contoso.com",
                "isMfaRegistered": False,
                "isMfaCapable": False,
                "isSsprRegistered": False,
                "isAdmin": True,
            },
            {
                "userPrincipalName": "bob@contoso.com",
                "isMfaRegistered": True,
                "isMfaCapable": True,
                "isSsprRegistered": True,
                "isAdmin": False,
            },
        ]
    }

    get_responses = [
        FakeResponse(200, users_payload),
        FakeResponse(200, registration_payload),
    ]
    fake_session = FakeSession(token_response, get_responses)

    monkeypatch.setattr(entra_main.aiohttp, "ClientSession", lambda timeout=None: fake_session)

    data = EntraIDSecurityAnalyzerInput(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        stale_threshold_days=90,
    )
    result = asyncio.run(entra_main.execute_tool(data))

    assert result.success is True
    assert result.total_users_scanned == 2

    assert len(result.stale_accounts) == 1
    assert result.stale_accounts[0].user_principal_name == "alice@contoso.com"
    assert result.stale_accounts[0].severity in {"Critical", "High", "Medium"}

    assert len(result.mfa_gaps) == 1
    assert result.mfa_gaps[0].user_principal_name == "alice@contoso.com"
    assert result.mfa_gaps[0].is_admin is True
    assert result.mfa_gaps[0].severity == "Critical"

    assert result.critical_issues >= 1
    assert any("MFA" in rec or "admin" in rec.lower() for rec in result.recommendations)


def test_token_failure_is_reported(monkeypatch):
    token_response = FakeResponse(401, {"error_description": "invalid_client"})
    fake_session = FakeSession(token_response, [])

    monkeypatch.setattr(entra_main.aiohttp, "ClientSession", lambda timeout=None: fake_session)

    data = EntraIDSecurityAnalyzerInput(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="wrong-secret",
    )
    result = asyncio.run(entra_main.execute_tool(data))

    assert result.success is False
    assert "invalid_client" in result.error_message
