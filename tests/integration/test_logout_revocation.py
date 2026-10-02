"""
Logging out must end the session at the gateway.

identity has a revocation endpoint (POST /auth/logout through the gateway,
open-security-identity/app/logout.py) that blacklists a token by its jti, and
the gateway's /internal/authorize consults that blacklist. That only works if
the tokens people actually hold carry a jti -- and the tokens from the login
endpoint, /api/v1/auth/jwt/login, are written by fastapi-users' JWTStrategy,
which puts nothing in them but sub, aud and exp.

These tests use the real login, the real gateway route and the real
protected API, and assert the outcome a user relies on: after logout, the
token no longer opens anything.
"""

import os
import time

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
PROTECTED = f"{GATEWAY_URL}/api/v1/data/health"


def _login() -> str:
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={
            "username": os.environ["TEST_ADMIN_EMAIL"],
            "password": os.environ["TEST_ADMIN_PASSWORD"],
        },
        timeout=10,
    )
    assert (
        response.status_code == 200
    ), f"login failed: {response.status_code} {response.text[:200]}"
    return response.json()["access_token"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_logout_revokes_a_login_token_at_the_gateway():
    token = _login()
    assert (
        requests.get(PROTECTED, headers=_bearer(token), timeout=10).status_code == 200
    )

    logout = requests.post(
        f"{GATEWAY_URL}/auth/logout", headers=_bearer(token), timeout=10
    )
    assert (
        logout.status_code == 200
    ), f"logout refused: {logout.status_code} {logout.text[:200]}"

    after = requests.get(PROTECTED, headers=_bearer(token), timeout=10)
    assert (
        after.status_code == 401
    ), f"token still accepted after logout: {after.status_code}"


def test_two_logins_in_the_same_second_are_two_sessions():
    """Without a unique claim, two logins within one second return the same
    token, so logging out of one would log out of the other (and the
    gateway's cache would treat them as one)."""
    tokens = {_login() for _ in range(3)}
    assert len(tokens) == 3, "login returned the same token for separate logins"


def test_logout_of_one_session_leaves_the_other_open():
    first = _login()
    time.sleep(1.1)
    second = _login()

    logout = requests.post(
        f"{GATEWAY_URL}/auth/logout", headers=_bearer(first), timeout=10
    )
    assert (
        logout.status_code == 200
    ), f"logout refused: {logout.status_code} {logout.text[:200]}"

    assert (
        requests.get(PROTECTED, headers=_bearer(first), timeout=10).status_code == 401
    )
    assert (
        requests.get(PROTECTED, headers=_bearer(second), timeout=10).status_code == 200
    )
