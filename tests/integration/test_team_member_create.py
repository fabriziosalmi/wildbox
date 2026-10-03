"""A team owner or admin creates an account in the team, on the running stack (#573).

POST /api/v1/identity/admin/teams/{team_id}/members creates an account
whose only membership is that team, with an initial password the
administrator chose. Until its user changes that password, identity and
the gateway refuse every other request of its sessions with
PASSWORD_CHANGE_REQUIRED. Each test registers its own owner directly at
identity, as test_account_change_hardening.py does; every request a
session makes goes through the gateway.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15

ACTIVITY = f"{GATEWAY_URL}/api/v1/identity/admin/me/activity"
CHANGE_PASSWORD = f"{GATEWAY_URL}/api/v1/identity/admin/me/change-password"
ME = f"{GATEWAY_URL}/auth/users/me"
# Authenticated by the gateway (auth_handler), not by identity.
PROTECTED = f"{GATEWAY_URL}/api/v1/data/health"


def email(label):
    return f"team-member-{label}-{secrets.token_hex(6)}@example.com"


def password():
    return f"Team-Member-{secrets.token_hex(8)}!"


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


def new_owner():
    """A registered account: the owner of the team registration gave it."""
    address, secret = email("owner"), password()
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": address, "password": secret},
        timeout=TIMEOUT,
    )
    assert response.status_code == 201, response.text[:200]
    token = login(address, secret)
    return token, team_of(token)


def team_of(token):
    response = requests.get(ACTIVITY, headers=bearer(token), timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:200]
    (membership,) = response.json()["team_memberships"]
    return membership["team_id"]


def members_url(team_id):
    return f"{GATEWAY_URL}/api/v1/identity/admin/teams/{team_id}/members"


def create_member(token, team_id, address, secret, role="member"):
    return requests.post(
        members_url(team_id),
        json={"email": address, "password": secret, "role": role},
        headers=bearer(token),
        timeout=TIMEOUT,
    )


def members(token, team_id):
    response = requests.get(
        members_url(team_id), headers=bearer(token), timeout=TIMEOUT
    )
    assert response.status_code == 200, response.text[:200]
    return {m["user"]["email"]: m["role"] for m in response.json()}


def error_message(response):
    body = response.json()
    if "error" in body and isinstance(body["error"], dict):
        return body["error"].get("message")
    return body.get("error")


def test_the_owner_creates_a_member_who_must_change_the_password_first():
    owner, team_id = new_owner()
    address, initial = email("new"), password()

    created = create_member(owner, team_id, address, initial)
    assert created.status_code == 201, created.text[:300]
    assert created.json()["role"] == "member"
    assert created.json()["user"]["must_change_password"] is True
    assert members(owner, team_id)[address] == "member"

    # The member logs in with the initial password...
    first = login(address, initial)
    me = requests.get(ME, headers=bearer(first), timeout=TIMEOUT)
    assert me.status_code == 200, me.text[:200]
    assert me.json()["must_change_password"] is True

    # ...and can use nothing else: not another service through the gateway,
    blocked = requests.get(PROTECTED, headers=bearer(first), timeout=TIMEOUT)
    assert blocked.status_code == 403, blocked.text[:200]
    assert error_message(blocked) == "PASSWORD_CHANGE_REQUIRED"
    # nor identity's own routes.
    own = requests.get(ACTIVITY, headers=bearer(first), timeout=TIMEOUT)
    assert own.status_code == 403, own.text[:200]
    assert error_message(own) == "PASSWORD_CHANGE_REQUIRED"

    new_password = password()
    changed = requests.post(
        CHANGE_PASSWORD,
        json={"current_password": initial, "new_password": new_password},
        headers=bearer(first),
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    fresh = changed.json()["access_token"]

    # The session now works, in the owner's team: the account's only one.
    allowed = requests.get(PROTECTED, headers=bearer(fresh), timeout=TIMEOUT)
    assert allowed.status_code == 200, allowed.text[:200]
    assert allowed.headers.get("X-Wildbox-Team-ID") == team_id
    assert team_of(fresh) == team_id
    me = requests.get(ME, headers=bearer(fresh), timeout=TIMEOUT)
    assert me.json()["must_change_password"] is False
    # The session that changed the password ended with the change (#569).
    gone = requests.get(PROTECTED, headers=bearer(first), timeout=TIMEOUT)
    assert gone.status_code == 401, gone.text[:200]


def test_a_member_cannot_create_accounts():
    owner, team_id = new_owner()
    address, initial = email("plain"), password()
    assert create_member(owner, team_id, address, initial).status_code == 201
    new_password = password()
    changed = requests.post(
        CHANGE_PASSWORD,
        json={"current_password": initial, "new_password": new_password},
        headers=bearer(login(address, initial)),
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    member = changed.json()["access_token"]

    refused = create_member(member, team_id, email("by-member"), password())
    assert refused.status_code == 403, refused.text[:200]
    # Nor in a team the caller does not belong to.
    _, other_team = new_owner()
    outside = create_member(owner, other_team, email("outside"), password())
    assert outside.status_code == 403, outside.text[:200]


def test_a_registered_email_is_a_conflict():
    owner, team_id = new_owner()
    address = email("twice")
    assert create_member(owner, team_id, address, password()).status_code == 201
    again = create_member(owner, team_id, address, password())
    assert again.status_code == 409, again.text[:200]
    # A registered account elsewhere, in other letter case, likewise.
    other_owner = email("registered")
    register = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": other_owner, "password": password()},
        timeout=TIMEOUT,
    )
    assert register.status_code == 201, register.text[:200]
    taken = create_member(owner, team_id, other_owner.upper(), password())
    assert taken.status_code == 409, taken.text[:200]
    assert other_owner not in taken.text.lower()


def test_no_one_creates_a_role_at_or_above_their_own():
    owner, team_id = new_owner()
    refused = create_member(owner, team_id, email("owner2"), password(), role="owner")
    assert refused.status_code == 403, refused.text[:200]

    admin_email, initial = email("admin"), password()
    created = create_member(owner, team_id, admin_email, initial, role="admin")
    assert created.status_code == 201, created.text[:200]
    changed = requests.post(
        CHANGE_PASSWORD,
        json={"current_password": initial, "new_password": password()},
        headers=bearer(login(admin_email, initial)),
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    admin = changed.json()["access_token"]

    peer = create_member(admin, team_id, email("peer-admin"), password(), role="admin")
    assert peer.status_code == 403, peer.text[:200]
    member = create_member(admin, team_id, email("by-admin"), password())
    assert member.status_code == 201, member.text[:200]
    roles = members(owner, team_id)
    assert sorted(roles.values()) == ["admin", "member", "owner"]
