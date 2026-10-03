"""A disabled API key stops working at the gateway on the next request (#593).

The gateway caches the decision for a key for AUTH_CACHE_TTL (300 s). Revoking
a key only marked it inactive in identity's database, so a key revoked because
it leaked kept working for up to five minutes on every route the gateway
authenticates. Identity now has the gateway refuse the key before it commits
the change -- and so does every other change that disables a key: an expiry,
an administrator's deactivation, the removal of the member from the team, the
deletion of the account.

Each test warms the gateway's cache with the key (two requests through the
gateway, both 200), disables it, and expects the very next request to be
refused. No retries and no waiting for the cache: either the gateway refuses
the key at once or the test fails. Every request goes through the gateway, as
a client's would; accounts are registered directly at identity, as
test_team_member_create.py does.
"""

import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
# Authenticated by the gateway (auth_handler), which caches the decision.
PROTECTED = f"{GATEWAY_URL}/api/v1/data/health"


def email(label):
    return f"key-revocation-{label}-{secrets.token_hex(6)}@example.com"


def password():
    return f"Key-Revocation-{secrets.token_hex(8)}!"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def login(address, secret):
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": address, "password": secret},
        timeout=TIMEOUT,
    )
    assert response.status_code == 200, response.text[:200]
    return response.json()["access_token"]


def register():
    """A new account, owner of the team registration gives it."""
    address, secret = email("owner"), password()
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": address, "password": secret},
        timeout=TIMEOUT,
    )
    assert response.status_code == 201, response.text[:200]
    return response.json()["id"], address, secret, login(address, secret)


def admin_session():
    return login(os.environ["TEST_ADMIN_EMAIL"], os.environ["TEST_ADMIN_PASSWORD"])


def create_key(token, **fields):
    response = requests.post(
        f"{IDENTITY_API}/api-keys",
        json={"name": f"revocation-{secrets.token_hex(4)}", **fields},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert response.status_code in (200, 201), response.text[:200]
    return response.json()


def use(key):
    return requests.get(PROTECTED, headers={"X-API-Key": key}, timeout=TIMEOUT)


def warm(key):
    """Two requests through the gateway: the second is served from its cache."""
    for _ in range(2):
        response = use(key)
        assert response.status_code == 200, response.text[:200]


def assert_refused_now(key, what):
    response = use(key)
    assert (
        response.status_code == 401
    ), f"the key still works at the gateway after {what}: {response.status_code}"


def test_a_revoked_key_is_refused_on_the_next_request():
    _, _, _, token = register()
    created = create_key(token)
    warm(created["key"])

    revoked = requests.delete(
        f"{IDENTITY_API}/api-keys/{created['prefix']}",
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 200, revoked.text[:200]

    assert_refused_now(created["key"], "its revocation")


def test_a_key_revoked_by_a_team_admin_is_refused_on_the_next_request():
    _, _, _, token = register()
    created = create_key(token)
    warm(created["key"])

    revoked = requests.delete(
        f"{IDENTITY_API}/teams/{created['team_id']}/api-keys/{created['prefix']}",
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 200, revoked.text[:200]

    assert_refused_now(created["key"], "its revocation by the team")


def test_an_expired_key_is_refused_although_its_decision_was_cached():
    _, _, _, token = register()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=6)
    created = create_key(token, expires_at=expires_at.isoformat())
    warm(created["key"])

    time.sleep(max(0.0, (expires_at - datetime.now(timezone.utc)).total_seconds()) + 1)

    assert_refused_now(created["key"], "its expiry")


def test_a_deactivated_account_s_key_and_session_are_refused():
    user_id, _, _, token = register()
    created = create_key(token)
    warm(created["key"])
    assert (
        requests.get(PROTECTED, headers=bearer(token), timeout=TIMEOUT).status_code
        == 200
    )

    deactivated = requests.patch(
        f"{IDENTITY_API}/admin/users/{user_id}/status",
        params={"is_active": "false"},
        headers=bearer(admin_session()),
        timeout=TIMEOUT,
    )
    assert deactivated.status_code == 200, deactivated.text[:200]

    assert_refused_now(created["key"], "the account's deactivation")
    session = requests.get(PROTECTED, headers=bearer(token), timeout=TIMEOUT)
    assert session.status_code == 401, session.status_code


def new_member(owner, team_id):
    """An account the owner creates in the team, past its first password change.

    Its only team is the owner's, so it is not the sole owner of a team,
    which an account must not be to delete itself.
    """
    address, initial = email("member"), password()
    member = requests.post(
        f"{IDENTITY_API}/admin/teams/{team_id}/members",
        json={"email": address, "password": initial, "role": "member"},
        headers=bearer(owner),
        timeout=TIMEOUT,
    )
    assert member.status_code == 201, member.text[:200]
    secret = password()
    changed = requests.post(
        f"{IDENTITY_API}/admin/me/change-password",
        json={"current_password": initial, "new_password": secret},
        headers=bearer(login(address, initial)),
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    return member.json()["user_id"], secret, changed.json()["access_token"]


def test_a_deleted_account_s_key_is_refused():
    _, _, _, owner = register()
    team_id = create_key(owner)["team_id"]
    _, secret, token = new_member(owner, team_id)
    created = create_key(token)
    warm(created["key"])

    deleted = requests.delete(
        f"{IDENTITY_API}/admin/me/account",
        json={"password": secret, "confirm_deletion": True},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert deleted.status_code == 200, deleted.text[:200]

    assert_refused_now(created["key"], "the account's deletion")


def test_a_removed_member_s_key_is_refused():
    _, _, _, owner = register()
    team_id = create_key(owner)["team_id"]
    member_id, _, token = new_member(owner, team_id)
    created = create_key(token)
    assert created["team_id"] == team_id
    warm(created["key"])

    removed = requests.delete(
        f"{IDENTITY_API}/admin/teams/{team_id}/members/{member_id}",
        headers=bearer(owner),
        timeout=TIMEOUT,
    )
    assert removed.status_code == 200, removed.text[:200]

    assert_refused_now(created["key"], "the member's removal from the team")


def test_revoking_one_key_leaves_another_working():
    _, _, _, token = register()
    first, second = create_key(token), create_key(token)
    warm(first["key"])
    warm(second["key"])

    revoked = requests.delete(
        f"{IDENTITY_API}/api-keys/{first['prefix']}",
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 200, revoked.text[:200]

    assert_refused_now(first["key"], "its revocation")
    assert use(second["key"]).status_code == 200


def test_a_key_of_an_account_deactivated_through_the_users_api_is_refused():
    """PATCH /users/{id} (fastapi-users) is the other way to deactivate."""
    user_id, _, _, token = register()
    created = create_key(token)
    warm(created["key"])

    deactivated = requests.patch(
        f"{IDENTITY_API}/users/{user_id}",
        json={"is_active": False},
        headers=bearer(admin_session()),
        timeout=TIMEOUT,
    )
    assert deactivated.status_code == 200, deactivated.text[:200]

    assert_refused_now(created["key"], "the account's deactivation")


def test_a_key_of_an_account_an_administrator_deletes_is_refused():
    user_id, _, _, token = register()
    created = create_key(token)
    warm(created["key"])

    deleted = requests.delete(
        f"{IDENTITY_API}/admin/users/{user_id}",
        params={"force": "true"},
        headers=bearer(admin_session()),
        timeout=TIMEOUT,
    )
    assert deleted.status_code == 200, deleted.text[:200]

    assert_refused_now(created["key"], "the account's deletion")
