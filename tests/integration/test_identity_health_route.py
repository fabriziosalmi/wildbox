"""identity's health probe through the gateway (#559).

The admin page probed /api/v1/identity/health, which the gateway mapped to
identity's /api/v1/health -- a path that does not exist (identity serves
/health) -- so the page always showed identity Offline and guessed Database
and Redis from that. The gateway now routes the probe, and identity reports
both dependencies from real checks.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15


def _member_token():
    email = f"health-{secrets.token_hex(6)}@example.com"
    password = f"Health-Probe-{secrets.token_hex(8)}!"
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


def test_identity_health_is_routed_and_reports_its_dependencies():
    response = requests.get(
        f"{GATEWAY_URL}/api/v1/identity/health",
        headers={"Authorization": f"Bearer {_member_token()}"},
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text[:200]
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["database"]["status"] == "healthy"
    assert body["checks"]["redis"]["status"] == "healthy"


def test_identity_health_requires_a_session():
    response = requests.get(f"{GATEWAY_URL}/api/v1/identity/health", timeout=TIMEOUT)
    assert response.status_code == 401
