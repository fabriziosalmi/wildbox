"""data tells a refused caller why in a body a client can read (#655).

A request that did not come through the gateway is refused by the shared
dependency (``open_security_shared.gateway_auth``), which raises a dict:
``{"error": <title>, "message": <explanation>, "code": <code>}``. The
error handler rendered it with ``str()``, so ``error.message`` was a Python
dict literal and the code could be read only by parsing it.

It is the canonical body now: ``error.message`` is the explanation and the
dict is JSON under ``error.details``, the code at ``error.details.code``.

Every service behind the shared dependency has this test, with the same
shape, against its real application.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api.main import app  # noqa: E402

# A route behind the gateway authentication dependency.
PATH = "/api/v1/sensors"

SECRET = "s" * 40
HEADERS = {
    "X-Wildbox-User-ID": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "X-Wildbox-Team-ID": "9c858901-8a57-4791-81fe-4c455b099bc9",
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": SECRET,
}

REFUSALS = [
    ("no identity headers", {}, 403, "GATEWAY_AUTH_REQUIRED"),
    (
        "a forged secret",
        {**HEADERS, "X-Gateway-Secret": "forged"},
        403,
        "GATEWAY_SECRET_REQUIRED",
    ),
    (
        "an unknown role",
        {**HEADERS, "X-Wildbox-Role": "root"},
        400,
        "INVALID_GATEWAY_HEADERS",
    ),
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    # No lifespan: the dependency refuses before the route runs.
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    "headers, status, code",
    [case[1:] for case in REFUSALS],
    ids=[case[0] for case in REFUSALS],
)
def test_a_refusal_carries_its_code_as_data(client, headers, status, code):
    response = client.get(PATH, headers=headers)

    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert error["code"] == status
    assert error["type"] == "HTTPException"
    assert error["request_id"]
    assert error["details"]["code"] == code
    assert set(error["details"]) == {"error", "message", "code"}
    # The explanation, and not the Python repr of the dict that carries it.
    assert error["message"] == error["details"]["message"]
    assert "{'" not in response.text
