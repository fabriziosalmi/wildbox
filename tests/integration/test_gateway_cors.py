"""CORS through the real gateway, in front of the real services (#712).

The gateway answered 405 to every OPTIONS request, so no CORS preflight was
ever answered and a dashboard served from another origin could log in and do
nothing else. It now decides CORS for the API in one place, for the origins
in ``CORS_ORIGINS`` and only those.

What only the running stack can show is the services behind it: identity,
data, tools and guardian have CORS middleware of their own, configured from
the same setting, and a response that carried the gateway's
``Access-Control-Allow-Origin`` and the service's would be refused by a
browser. These tests read the gateway's own ``CORS_ORIGINS`` from its
container, call as a page on the first listed origin would, and check that
each service's response names that origin exactly once; and that a page on
an origin nobody listed gets no preflight and no name.
"""

import os
import secrets
import shutil
import subprocess

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
GATEWAY_CONTAINER = os.getenv("GATEWAY_CONTAINER", "open-security-gateway")
TIMEOUT = 30

UNLISTED = "https://not-listed.example"

# One route of each service that has CORS middleware of its own.
SERVICE_ROUTES = [
    ("identity", "/api/v1/identity/users/me"),
    ("data", "/api/v1/data/sources"),
    ("tools", "/api/v1/tools"),
    ("guardian", "/api/v1/guardian/assets/assets/"),
]


def _unavailable(reason):
    if os.getenv("REQUIRE_ALL_SERVICES", "") in ("1", "true", "yes"):
        pytest.fail(f"{reason}, and REQUIRE_ALL_SERVICES is set", pytrace=False)
    pytest.skip(reason)


@pytest.fixture(scope="module")
def listed():
    """The first origin the running gateway lists in CORS_ORIGINS."""
    if shutil.which("docker") is None:
        _unavailable("docker is not available to read the gateway's CORS_ORIGINS")
    result = subprocess.run(
        ["docker", "exec", GATEWAY_CONTAINER, "printenv", "CORS_ORIGINS"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 and "No such container" in result.stderr:
        _unavailable(f"{GATEWAY_CONTAINER} is not running")
    origins = [
        entry.strip()
        for entry in result.stdout.strip().strip("[]").replace('"', "").split(",")
    ]
    origins = [origin for origin in origins if origin]
    if not origins:
        _unavailable("the gateway lists no origin in CORS_ORIGINS")
    return origins[0]


@pytest.fixture(scope="module")
def session():
    """Bearer headers of a newly registered account."""
    email = f"gateway-cors-{secrets.token_hex(6)}@example.com"
    password = f"Gateway-Cors-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _preflight(path, origin, method="POST"):
    return requests.options(
        f"{GATEWAY_URL}{path}",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": "authorization, content-type",
        },
        timeout=TIMEOUT,
    )


def _cors_headers(response):
    return {
        name: value
        for name, value in response.headers.items()
        if name.lower().startswith("access-control-")
    }


@pytest.mark.parametrize("service,path", SERVICE_ROUTES)
def test_a_preflight_from_a_listed_origin_is_answered_without_credentials(
    listed, service, path
):
    response = _preflight(path, listed)

    assert (
        response.status_code == 204
    ), f"{service}: {response.status_code} {response.text[:200]}"
    assert response.headers["Access-Control-Allow-Origin"] == listed
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "authorization" in response.headers["Access-Control-Allow-Headers"].lower()
    assert "origin" in response.headers.get("Vary", "").lower()
    assert response.content == b""


@pytest.mark.parametrize("service,path", SERVICE_ROUTES)
def test_a_preflight_from_an_unlisted_origin_is_refused(service, path):
    response = _preflight(path, UNLISTED)

    assert response.status_code == 405, f"{service}: {response.status_code}"
    assert _cors_headers(response) == {}


@pytest.mark.parametrize("service,path", SERVICE_ROUTES)
def test_a_service_response_names_the_listed_origin_exactly_once(
    listed, session, service, path
):
    """The service has CORS middleware too: two values would be refused by a browser."""
    response = requests.get(
        f"{GATEWAY_URL}{path}", headers={**session, "Origin": listed}, timeout=TIMEOUT
    )

    assert (
        response.status_code == 200
    ), f"{service}: {response.status_code} {response.text[:200]}"
    # requests joins repeated header lines with ", ": one value, no comma.
    assert response.headers["Access-Control-Allow-Origin"] == listed, service
    assert response.headers["Access-Control-Allow-Credentials"] == "true", service
    assert "origin" in response.headers.get("Vary", "").lower(), service


@pytest.mark.parametrize("service,path", SERVICE_ROUTES)
def test_a_service_response_names_nobody_for_an_unlisted_origin(session, service, path):
    response = requests.get(
        f"{GATEWAY_URL}{path}", headers={**session, "Origin": UNLISTED}, timeout=TIMEOUT
    )

    assert (
        response.status_code == 200
    ), f"{service}: {response.status_code} {response.text[:200]}"
    assert _cors_headers(response) == {}, service


def test_the_gateway_s_own_refusal_is_readable_by_the_listed_origin(listed):
    response = requests.get(
        f"{GATEWAY_URL}/api/v1/data/sources",
        headers={"Origin": listed},
        timeout=TIMEOUT,
    )

    assert response.status_code == 401
    assert response.headers["Access-Control-Allow-Origin"] == listed


def test_the_dashboard_s_pages_are_not_labelled(listed):
    response = requests.get(
        f"{GATEWAY_URL}/auth/login", headers={"Origin": listed}, timeout=TIMEOUT
    )

    # Whatever the dashboard answers (it may not be running in this stack),
    # the page is not the API and names nobody.
    assert _cors_headers(response) == {}
    assert _preflight("/auth/login", listed, method="GET").status_code == 405


def test_an_options_request_that_is_not_a_preflight_is_still_refused():
    response = requests.options(f"{GATEWAY_URL}/api/v1/data/sources", timeout=TIMEOUT)

    assert response.status_code == 405
    assert response.json()["error"] == "method_not_allowed"
