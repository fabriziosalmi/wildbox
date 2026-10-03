"""Who may read identity's admin metrics and revoke an API key (#664).

The admin metrics trusted the X-Gateway-Secret header alone, and the gateway
stamped that header on every request it passed through to identity, so an
anonymous GET /api/v1/identity/admin/metrics read the platform's business
counts. The route now requires a platform superuser, authenticated by
identity from the bearer token, and the gateway forwards its secret only on
the requests it authenticated.

Every request goes through the gateway, as a client's would; accounts are
registered directly at identity, as test_api_key_revocation.py does.
"""

import os
import secrets

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
METRICS = f"{IDENTITY_API}/admin/metrics"
# Authenticated by the gateway (auth_handler), which asks identity's
# /internal/authorize and forwards the secret the data service checks.
PROTECTED = f"{GATEWAY_URL}/api/v1/data/health"


def email(label):
    return f"identity-access-{label}-{secrets.token_hex(6)}@example.com"


def password():
    return f"Identity-Access-{secrets.token_hex(8)}!"


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
    return response.json()["id"], login(address, secret)


def admin_session():
    return login(os.environ["TEST_ADMIN_EMAIL"], os.environ["TEST_ADMIN_PASSWORD"])


def assert_refused(response, what):
    assert response.status_code in (401, 403), f"{what}: {response.status_code}"
    assert "users_total" not in response.text, f"{what}: the counts were served"


# -- admin metrics ------------------------------------------------------------


def test_anonymous_metrics_are_refused():
    assert_refused(requests.get(METRICS, timeout=TIMEOUT), "anonymous")


def test_a_forged_gateway_secret_does_not_open_the_metrics():
    forged = {"X-Gateway-Secret": secrets.token_hex(32)}
    assert_refused(
        requests.get(METRICS, headers=forged, timeout=TIMEOUT), "forged secret"
    )


def test_the_real_gateway_secret_alone_does_not_open_the_metrics():
    """Not even the right value, through the gateway or straight to identity.

    The gateway drops the header on its identity passthrough, and identity
    no longer reads it on this route: either alone would refuse.
    """
    secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not secret:
        pytest.skip("GATEWAY_INTERNAL_SECRET is not set for the suite")
    header = {"X-Gateway-Secret": secret}
    assert_refused(
        requests.get(METRICS, headers=header, timeout=TIMEOUT),
        "the gateway secret through the gateway",
    )
    assert_refused(
        requests.get(
            f"{IDENTITY_URL}/api/v1/admin/metrics", headers=header, timeout=TIMEOUT
        ),
        "the gateway secret straight to identity",
    )


def test_a_team_owner_is_not_a_platform_superuser():
    _, token = register()
    response = requests.get(METRICS, headers=bearer(token), timeout=TIMEOUT)
    assert response.status_code == 403, response.status_code
    assert "users_total" not in response.text


def test_a_superuser_reads_the_metrics():
    response = requests.get(METRICS, headers=bearer(admin_session()), timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:200]
    counts = response.json()["metrics"]
    assert "error" not in counts, counts
    # The superuser itself is one of them, and owns at least one team.
    assert counts["users_total"] >= 1 and counts["teams_total"] >= 1


def test_authenticated_routes_still_reach_the_services():
    """The gateway still asks /internal/authorize with its secret, and still
    forwards the secret to the service on the requests it authenticated."""
    _, token = register()
    response = requests.get(PROTECTED, headers=bearer(token), timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:200]


# -- API keys -----------------------------------------------------------------


def create_key(token):
    response = requests.post(
        f"{IDENTITY_API}/api-keys",
        json={"name": f"access-{secrets.token_hex(4)}"},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert response.status_code in (200, 201), response.text[:200]
    return response.json()


def use(key):
    return requests.get(PROTECTED, headers={"X-API-Key": key}, timeout=TIMEOUT)


def new_member(owner, team_id):
    """An account the owner creates in the team, past its first password change.

    Its only team is the owner's, which is therefore its primary team: the
    one the self-service key routes act in.
    """
    address, initial = email("member"), password()
    member = requests.post(
        f"{IDENTITY_API}/admin/teams/{team_id}/members",
        json={"email": address, "password": initial, "role": "member"},
        headers=bearer(owner),
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
    return changed.json()["access_token"]


def team_with_member():
    _, owner = register()
    owner_key = create_key(owner)
    return owner, owner_key, new_member(owner, owner_key["team_id"])


def test_a_member_cannot_revoke_the_owner_s_key():
    _, owner_key, member = team_with_member()
    assert use(owner_key["key"]).status_code == 200

    revoked = requests.delete(
        f"{IDENTITY_API}/api-keys/{owner_key['prefix']}",
        headers=bearer(member),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 404, revoked.text[:200]
    assert use(owner_key["key"]).status_code == 200, "the owner's key was revoked"

    # Nor read it, nor see it listed, through the self-service routes.
    read = requests.get(
        f"{IDENTITY_API}/api-keys/{owner_key['prefix']}",
        headers=bearer(member),
        timeout=TIMEOUT,
    )
    assert read.status_code == 404, read.text[:200]
    listed = requests.get(
        f"{IDENTITY_API}/api-keys", headers=bearer(member), timeout=TIMEOUT
    )
    assert listed.status_code == 200, listed.text[:200]
    assert owner_key["prefix"] not in {key["prefix"] for key in listed.json()}


def test_a_member_cannot_revoke_through_the_team_route():
    _, owner_key, member = team_with_member()
    revoked = requests.delete(
        f"{IDENTITY_API}/teams/{owner_key['team_id']}/api-keys/{owner_key['prefix']}",
        headers=bearer(member),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 403, revoked.text[:200]
    assert use(owner_key["key"]).status_code == 200


def test_the_owner_revokes_a_member_s_key_through_the_team_route():
    owner, _, member = team_with_member()
    member_key = create_key(member)
    for _ in range(2):  # the second request is served from the gateway's cache
        assert use(member_key["key"]).status_code == 200

    # The self-service route is the owner's own keys only.
    own_only = requests.delete(
        f"{IDENTITY_API}/api-keys/{member_key['prefix']}",
        headers=bearer(owner),
        timeout=TIMEOUT,
    )
    assert own_only.status_code == 404, own_only.text[:200]
    assert use(member_key["key"]).status_code == 200

    revoked = requests.delete(
        f"{IDENTITY_API}/teams/{member_key['team_id']}/api-keys/{member_key['prefix']}",
        headers=bearer(owner),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 200, revoked.text[:200]
    assert use(member_key["key"]).status_code == 401


def test_a_member_revokes_their_own_key():
    _, _, member = team_with_member()
    member_key = create_key(member)
    assert use(member_key["key"]).status_code == 200
    revoked = requests.delete(
        f"{IDENTITY_API}/api-keys/{member_key['prefix']}",
        headers=bearer(member),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 200, revoked.text[:200]
    assert use(member_key["key"]).status_code == 401
