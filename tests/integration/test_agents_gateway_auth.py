"""The agents routes through the gateway, signed in with a session (#630).

/api/v1/agents/* authenticated with its own inline Lua, which read X-API-Key
only: a signed-in user's JWT got 401 NO_API_KEY on every agents route,
although the documentation says a JWT or an API key works across the
gateway. The route now goes through auth_handler.authenticate(), like every
other one. The agents service needs its Anthropic key to run an analysis,
not to accept one: the submission is stored and queued, and answered 202.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 20
ANALYSIS = {"ioc": {"type": "ipv4", "value": "8.8.8.8"}, "priority": "normal"}


def _session_token():
    """A new account's session token, from identity's login."""
    email = f"agents-{secrets.token_hex(6)}@example.com"
    password = f"Agents-Route-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert response.status_code == 200, response.text[:200]
    return response.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_a_session_submits_an_analysis_and_reads_it_back():
    token = _session_token()

    submitted = requests.post(
        f"{GATEWAY_URL}/api/v1/agents/analyze",
        json=ANALYSIS,
        headers=_bearer(token),
        timeout=TIMEOUT,
    )

    assert submitted.status_code == 202, submitted.text[:300]
    task_id = submitted.json()["task_id"]

    # The task is recorded under the user the gateway forwarded: its owner
    # reads it, and another account is refused by the service.
    read = requests.get(
        f"{GATEWAY_URL}/api/v1/agents/analyze/{task_id}",
        headers=_bearer(token),
        timeout=TIMEOUT,
    )
    assert read.status_code == 200, read.text[:300]
    assert read.json()["task_id"] == task_id

    other = requests.get(
        f"{GATEWAY_URL}/api/v1/agents/analyze/{task_id}",
        headers=_bearer(_session_token()),
        timeout=TIMEOUT,
    )
    # Another user's task answers like a task that does not exist (#650),
    # so a task id cannot be probed.
    assert other.status_code == 404, other.text[:300]


def test_the_agents_routes_require_a_credential():
    response = requests.post(
        f"{GATEWAY_URL}/api/v1/agents/analyze", json=ANALYSIS, timeout=TIMEOUT
    )

    assert response.status_code == 401
    assert response.json()["error"] == "authentication_required"


def test_the_service_statistics_are_routed():
    # /api/v1/agents/stats mapped to /v1/stats, which the service does not
    # have; its statistics are at /stats.
    response = requests.get(
        f"{GATEWAY_URL}/api/v1/agents/stats",
        headers=_bearer(_session_token()),
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text[:300]
    assert "total_analyses" in response.json()
