"""The password policy, through the gateway on the running stack (#583).

Registration accepted a one-character password: fastapi-users checks
nothing unless UserManager.validate_password() does, and identity did not
override it. Now registration, reset-password, change-password and an
administrator's reset all refuse a password shorter than 12 characters,
longer than 128, containing the account's email or its local part, or one of
the most common passwords.

Registration is sent the way the dashboard sends it, to the gateway's
/auth/register. That route is rate limited per address (5 a second, burst
2). A 429 used to be retried here; the stack the suite runs against is now
given a rate the suite does not reach (conftest.py, #756), and a 429 is an
answer like any other: the assertions below fail on it.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15

REGISTER = f"{GATEWAY_URL}/auth/register"
CHANGE_PASSWORD = f"{GATEWAY_URL}/api/v1/identity/admin/me/change-password"


def new_email():
    return f"password-policy-{secrets.token_hex(6)}@example.com"


def strong_password():
    return f"Policy-Check-{secrets.token_hex(8)}"


def register(email, password):
    return requests.post(
        REGISTER, json={"email": email, "password": password}, timeout=TIMEOUT
    )


def assert_refused(response, mention):
    assert response.status_code == 400, response.text[:200]
    # The canonical error body (open_security_shared.errors): fastapi-users'
    # reason is the message a person reads, its code is in details.
    error = response.json()["error"]
    assert error["details"]["code"] == "REGISTER_INVALID_PASSWORD"
    assert mention in error["message"].lower()


def test_register_refuses_a_short_password():
    assert_refused(register(new_email(), "a"), "at least 12")


def test_register_refuses_a_common_password():
    assert_refused(register(new_email(), "password1234"), "common")


def test_register_refuses_a_password_containing_the_email():
    email = new_email()
    assert_refused(register(email, f"{email}-pw"), "email")


def test_register_accepts_a_valid_password():
    assert register(new_email(), strong_password()).status_code == 201


def test_change_password_refuses_a_common_password():
    email, password = new_email(), strong_password()
    assert register(email, password).status_code == 201
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    token = login.json()["access_token"]

    response = requests.post(
        CHANGE_PASSWORD,
        json={"current_password": password, "new_password": "qwerty123456"},
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT,
    )
    assert response.status_code == 400, response.text[:200]
    assert "common" in response.json()["error"]["message"].lower()
