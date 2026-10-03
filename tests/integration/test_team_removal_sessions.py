"""A member removed from a team loses the team at the gateway at once (#613).

A session is not bound to a team: /internal/authorize resolves one on every
request -- the oldest membership -- and the gateway caches the answer for
AUTH_CACHE_TTL (300 s). Removing a member revoked their API keys for the team
(#593), but their sessions kept the cached "allowed in this team" decision,
and the removed member went on acting in the team for up to five minutes.
Identity now has the gateway refuse, in that team only, the member's
sessions issued up to the removal before it commits it.

Each test warms the gateway's cache with the member's session (two requests
through the gateway, both 200, in the team), has the owner remove the
member, and expects the very next request with the same session to be
refused. No retries and no waiting for the cache. The refused decision is
dropped, so the request after it is authorized afresh: identity no longer
resolves the team the member left, and a member who still belongs to
another team is served there.

A second membership cannot be made through the API -- an account is created
in one team and cannot be added to another -- so that test writes the row
into identity's database, as test_data_cross_tenant.py seeds the data
service's.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
# Authenticated by the gateway (auth_handler), which caches the decision.
PROTECTED = f"{GATEWAY_URL}/api/v1/data/health"


def email(label):
    return f"team-removal-{label}-{secrets.token_hex(6)}@example.com"


def password():
    return f"Team-Removal-{secrets.token_hex(8)}!"


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


def owner():
    """A new account and the team registration gives it: (session, team id)."""
    address, secret = email("owner"), password()
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": address, "password": secret},
        timeout=TIMEOUT,
    )
    assert response.status_code == 201, response.text[:200]
    token = login(address, secret)
    return token, use(token).headers["X-Wildbox-Team-ID"]


def new_member(owner_token, team_id):
    """An account the owner creates in the team, past its first password
    change: (user id, session)."""
    address, initial = email("member"), password()
    member = requests.post(
        f"{IDENTITY_API}/admin/teams/{team_id}/members",
        json={"email": address, "password": initial, "role": "member"},
        headers=bearer(owner_token),
        timeout=TIMEOUT,
    )
    assert member.status_code == 201, member.text[:200]
    changed = requests.post(
        f"{IDENTITY_API}/admin/me/change-password",
        json={"current_password": initial, "new_password": password()},
        headers=bearer(login(address, initial)),
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    return member.json()["user_id"], changed.json()["access_token"]


def use(token):
    return requests.get(PROTECTED, headers=bearer(token), timeout=TIMEOUT)


def warm(token, team_id):
    """Two requests through the gateway, in the team: the second is served
    from its cache."""
    for _ in range(2):
        response = use(token)
        assert response.status_code == 200, response.text[:200]
        assert response.headers.get("X-Wildbox-Team-ID") == team_id


def remove(owner_token, team_id, user_id):
    removed = requests.delete(
        f"{IDENTITY_API}/admin/teams/{team_id}/members/{user_id}",
        headers=bearer(owner_token),
        timeout=TIMEOUT,
    )
    assert removed.status_code == 200, removed.text[:200]


def assert_refused_in_the_team(token):
    response = use(token)
    assert response.status_code == 403, (
        "the session still works in the team after the member's removal: "
        f"{response.status_code} {response.headers.get('X-Wildbox-Team-ID')}"
    )
    assert response.json().get("error") == "team_membership_ended"


def test_a_removed_member_s_session_is_refused_on_the_next_request():
    owner_token, team_id = owner()
    member_id, session = new_member(owner_token, team_id)
    warm(session, team_id)

    remove(owner_token, team_id, member_id)

    assert_refused_in_the_team(session)
    # The member has no team left: identity refuses the session afresh.
    assert use(session).status_code == 401
    # The owner, in the same team, is not affected.
    assert use(owner_token).status_code == 200


def test_a_member_with_another_team_goes_on_in_that_team():
    psycopg2 = pytest.importorskip("psycopg2")
    dsn = os.environ.get("IDENTITY_DB_DSN", "")
    if not dsn:
        pytest.skip("IDENTITY_DB_DSN not set")

    owner_token, team_id = owner()
    _, other_team_id = owner()
    member_id, session = new_member(owner_token, team_id)
    # A later membership in a second team: the session still resolves the
    # first, its oldest.
    with psycopg2.connect(dsn) as conn, conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO team_memberships (user_id, team_id, role, joined_at) "
            "VALUES (%s, %s, 'member', %s)",
            (
                member_id,
                other_team_id,
                datetime.now(timezone.utc) + timedelta(seconds=1),
            ),
        )
    conn.close()
    warm(session, team_id)

    remove(owner_token, team_id, member_id)

    # The same session: refused in the team it left, once...
    assert_refused_in_the_team(session)
    # ...then authorized afresh, in the team the member still belongs to.
    for _ in range(2):
        response = use(session)
        assert response.status_code == 200, response.text[:200]
        assert response.headers.get("X-Wildbox-Team-ID") == other_team_id
