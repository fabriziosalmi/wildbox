"""The tools service authenticates only requests that come through the gateway.

A static X-API-Key used to be accepted directly by ``get_current_user`` and
answered with a GatewayUser built on the nil UUID, which ``GatewayUser``
refuses (it declares UUID4), so every such request ended in a server error
(#565). That path is gone: a request authenticates with the gateway's
X-Wildbox-* headers and the X-Gateway-Secret proof of origin, or it gets 401.
"""

import os
import sys
import uuid

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

SERVICE_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
os.environ.setdefault("API_KEY", SERVICE_KEY)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.auth import get_current_user  # noqa: E402
from app.config import settings  # noqa: E402
from open_security_shared.gateway_auth import GatewayUser  # noqa: E402

GATEWAY_SECRET = "unit-test-gateway-secret-0123456789"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", GATEWAY_SECRET)
    app = FastAPI()

    @app.get("/whoami")
    async def whoami(user: GatewayUser = Depends(get_current_user)):
        return {"user_id": str(user.user_id), "role": user.role}

    return TestClient(app, raise_server_exceptions=False)


def gateway_headers(user_id, team_id, secret=GATEWAY_SECRET):
    return {
        "X-Wildbox-User-ID": user_id,
        "X-Wildbox-Team-ID": team_id,
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": secret,
    }


def test_service_api_key_alone_is_refused(client):
    # The configured key itself, so this is not a wrong-key rejection.
    response = client.get("/whoami", headers={"X-API-Key": settings.get_api_key()})

    assert response.status_code == 401
    assert "X-API-Key" not in response.json()["detail"]
    assert "gateway" in response.json()["detail"]


def test_wrong_api_key_alone_is_refused(client):
    response = client.get("/whoami", headers={"X-API-Key": "not-the-key"})

    assert response.status_code == 401


def test_no_credentials_is_refused(client):
    response = client.get("/whoami")

    assert response.status_code == 401
    assert "X-API-Key" not in response.json()["detail"]


def test_gateway_identity_is_accepted(client):
    user_id = str(uuid.uuid4())

    response = client.get(
        "/whoami", headers=gateway_headers(user_id, str(uuid.uuid4()))
    )

    assert response.status_code == 200
    assert response.json() == {"user_id": user_id, "role": "member"}


def test_gateway_identity_wins_over_a_stray_api_key(client):
    user_id = str(uuid.uuid4())
    headers = gateway_headers(user_id, str(uuid.uuid4()))
    headers["X-API-Key"] = settings.get_api_key()

    response = client.get("/whoami", headers=headers)

    assert response.status_code == 200
    assert response.json()["user_id"] == user_id


def test_gateway_headers_without_the_secret_are_refused(client):
    headers = gateway_headers(str(uuid.uuid4()), str(uuid.uuid4()), secret="forged")

    response = client.get("/whoami", headers=headers)

    assert response.status_code in (401, 403)
