"""Profile and password changes through the gateway (#559).

The dashboard's profile page sent PUT /api/v1/users/me and
PUT /api/v1/users/me/password, which the gateway does not route, so neither
ever saved. It now uses the routes below, and these tests pin what each one
does on the running stack:

- PATCH /auth/users/me (fastapi-users) changes the email, and refuses a
  password: it applied one without asking for the current password, so a
  stolen session token could take the account over;
- POST /api/v1/identity/admin/me/change-password changes the password only
  with the current one.

Every account here is registered for the test (directly at identity, which
keeps the gateway's auth rate limit out of it), so the wrong-password
attempts never count towards the stack admin's lockout.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15


def new_account():
    email = f"self-service-{secrets.token_hex(6)}@example.com"
    password = f"Self-Service-{secrets.token_hex(8)}!"
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


def test_patch_me_refuses_to_change_the_password():
    email, password = new_account()
    token = token_for(email, password)
    new_password = f"Taken-Over-{secrets.token_hex(8)}!"

    response = requests.patch(
        f"{GATEWAY_URL}/auth/users/me",
        json={"password": new_password},
        headers=bearer(token),
        timeout=TIMEOUT,
    )

    assert response.status_code == 400, response.text[:200]
    assert response.json()["detail"]["code"] == "UPDATE_USER_INVALID_PASSWORD"
    assert login(email, password).status_code == 200
    assert login(email, new_password).status_code == 400


def test_patch_me_changes_the_email():
    email, password = new_account()
    token = token_for(email, password)
    new_email = f"renamed-{secrets.token_hex(6)}@example.com"

    response = requests.patch(
        f"{GATEWAY_URL}/auth/users/me",
        json={"email": new_email},
        headers=bearer(token),
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text[:200]
    me = requests.get(
        f"{GATEWAY_URL}/auth/users/me", headers=bearer(token), timeout=TIMEOUT
    )
    assert me.json()["email"] == new_email
    assert login(new_email, password).status_code == 200


def test_change_password_requires_the_current_password():
    email, password = new_account()
    token = token_for(email, password)
    new_password = f"Changed-{secrets.token_hex(8)}!"
    url = f"{GATEWAY_URL}/api/v1/identity/admin/me/change-password"

    wrong = requests.post(
        url,
        json={"current_password": "not-the-password", "new_password": new_password},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert wrong.status_code == 400, wrong.text[:200]
    assert login(email, new_password).status_code == 400

    right = requests.post(
        url,
        json={"current_password": password, "new_password": new_password},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert right.status_code == 200, right.text[:200]
    assert login(email, new_password).status_code == 200
    assert login(email, password).status_code == 400
