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
