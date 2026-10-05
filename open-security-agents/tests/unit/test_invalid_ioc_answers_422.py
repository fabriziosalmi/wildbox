"""An IOC value of the wrong format is the caller's mistake: 422, not 500.

``IOCInput`` checks the value against the pattern of its type and raises
``ValueError``. pydantic keeps that exception object in the field error, the
shared validation handler passed the errors to the response as they were, and
the response could not be rendered as JSON: ``POST /v1/analyze`` answered 500
"An internal error occurred" to ``{"type": "ipv4", "value": "not-an-ip"}``.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.main import app  # noqa: E402

SECRET = "s" * 40
HEADERS = {
    "X-Wildbox-User-ID": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "X-Wildbox-Team-ID": "9c858901-8a57-4791-81fe-4c455b099bc9",
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": SECRET,
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    # No lifespan: the body is refused before the route runs.
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    "ioc",
    [
        {"type": "ipv4", "value": "not-an-ip"},
        {"type": "sha256", "value": "abc"},
        {"type": "email", "value": "nobody"},
    ],
)
def test_a_malformed_ioc_value_is_a_field_error(client, ioc):
    response = client.post("/v1/analyze", headers=HEADERS, json={"ioc": ioc})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == 422
    assert error["type"] == "ValidationError"
    assert error["message"] == "Request validation failed"
    [item] = error["details"]
    assert item["loc"] == ["body", "ioc", "value"]
    assert f"Invalid format for {ioc['type']} IOC" in item["msg"]
