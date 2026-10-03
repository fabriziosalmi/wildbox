"""Account changes a stolen session could still make, on the running stack (#569).

Each test registers its own account directly at identity (which keeps the
gateway's auth rate limit out of it), so the wrong passwords tried here never
count towards the stack admin's lockout. Every request that a session makes
goes through the gateway, the way the dashboard sends it.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15
# identity's MAX_FAILED_LOGIN_ATTEMPTS default, as in test_login_lockout.py.
MAX_ATTEMPTS = 5

CHANGE_PASSWORD = f"{GATEWAY_URL}/api/v1/identity/admin/me/change-password"
PATCH_ME = f"{GATEWAY_URL}/auth/users/me"
PROFILE = f"{GATEWAY_URL}/api/v1/identity/admin/me/profile"


def new_account():
    email = f"account-change-{secrets.token_hex(6)}@example.com"
    password = f"Account-Change-{secrets.token_hex(8)}!"
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert response.status_code == 201, response.text[:200]
    return email, password


def login(email, password):
    return requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )


def token_for(email, password):
    response = login(email, password)
    assert response.status_code == 200, response.text[:200]
    return response.json()["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def change_password(token, current, new):
    return requests.post(
        CHANGE_PASSWORD,
        json={"current_password": current, "new_password": new},
        headers=bearer(token),
        timeout=TIMEOUT,
    )


def email_of(token):
    me = requests.get(PATCH_ME, headers=bearer(token), timeout=TIMEOUT)
    assert me.status_code == 200, me.text[:200]
    return me.json()["email"]


def test_an_email_change_without_the_current_password_is_refused():
    email, password = new_account()
    token = token_for(email, password)
    new_email = f"taken-over-{secrets.token_hex(6)}@example.com"

    # Two wrong passwords in all, below the lockout threshold.
    for url in (PATCH_ME, PROFILE):
        for body in (
            {"email": new_email},
            {"email": new_email, "current_password": "not-the-password"},
        ):
            response = requests.patch(
                url, json=body, headers=bearer(token), timeout=TIMEOUT
            )
            assert response.status_code == 400, (url, response.text[:200])

    assert email_of(token) == email
    assert login(new_email, password).status_code == 400


def test_an_email_change_with_the_current_password_is_saved():
    email, password = new_account()
    token = token_for(email, password)
    new_email = f"moved-{secrets.token_hex(6)}@example.com"

    response = requests.patch(
        PROFILE,
        json={"email": new_email, "current_password": password},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert response.status_code == 200, response.text[:200]
    assert email_of(token) == new_email
    assert login(new_email, password).status_code == 200


def test_repeated_wrong_current_passwords_lock_the_account():
    email, password = new_account()
    token = token_for(email, password)
    new_password = f"Guessed-{secrets.token_hex(8)}!"

    for attempt in range(MAX_ATTEMPTS):
        wrong = change_password(token, f"guess-{attempt}", new_password)
        assert wrong.status_code == 400, wrong.text[:200]

    # Locked like a login: the right password is refused as well.
    locked = change_password(token, password, new_password)
    assert locked.status_code == 429, locked.text[:200]
    assert "Retry-After" in locked.headers
    assert login(email, password).status_code == 429
