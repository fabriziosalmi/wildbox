"""Per-account lockout on password login, against the running stack (#509).

identity had the lockout helpers and settings (5 attempts, 15 minutes) but
nothing called them, so an account accepted unlimited password guesses.
Each test registers its own account so the admin used by the rest of the
suite is never locked.
"""

import os
import uuid

import requests

IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
MAX_ATTEMPTS = 5
PASSWORD = "Lockout-Test-Pass-123!"


def _register():
    email = f"lockout-{uuid.uuid4().hex[:12]}@example.com"
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": PASSWORD},
        timeout=15,
    )
    assert response.status_code in (200, 201), response.text[:200]
    return email


def _login(email, password):
    return requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=15,
    )


def test_account_locks_after_repeated_failures():
    email = _register()
    for _ in range(MAX_ATTEMPTS):
        assert _login(email, "wrong-password").status_code == 400

    locked = _login(email, PASSWORD)
    assert locked.status_code == 429, f"expected lockout, got {locked.status_code}"
    assert "Retry-After" in locked.headers


def test_successful_login_resets_the_counter():
    email = _register()
    for _ in range(MAX_ATTEMPTS - 1):
        assert _login(email, "wrong-password").status_code == 400
    assert _login(email, PASSWORD).status_code == 200

    for _ in range(MAX_ATTEMPTS - 1):
        assert _login(email, "wrong-password").status_code == 400
    assert _login(email, PASSWORD).status_code == 200


def test_unknown_account_locks_the_same_way():
    """The response must not tell registered from unregistered emails."""
    email = f"nobody-{uuid.uuid4().hex[:12]}@example.com"
    for _ in range(MAX_ATTEMPTS):
        assert _login(email, "wrong-password").status_code == 400
    assert _login(email, "wrong-password").status_code == 429
