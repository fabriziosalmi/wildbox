"""
Tests for the canonical error contract.

Four incompatible error shapes used to be served under one API, and the
dashboard's client read a field three of them did not have, so most server
explanations never reached a user (WILDBO-API-01/API-02). These tests pin the
one shape every service now installs.
"""

import math
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from open_security_shared.errors import REQUEST_ID_HEADER, install_error_handlers
from open_security_shared.gateway_auth import (
    get_user_from_gateway_headers,
    require_role,
)
from pydantic import BaseModel, field_validator


class Body(BaseModel):
    value: int


class ErrorCode(str, Enum):
    """How fastapi-users raises its codes (fastapi_users.router.common)."""

    REGISTER_USER_ALREADY_EXISTS = "REGISTER_USER_ALREADY_EXISTS"


@pytest.fixture
def client():
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/ok")
    def ok():
        return {"ok": True}

    @app.get("/forbidden")
    def forbidden():
        raise HTTPException(status_code=403, detail="Direct access is not permitted")

    @app.post("/register")
    def register():
        # fastapi-users' shape for a refused password.
        raise HTTPException(
            status_code=400,
            detail={"code": "REGISTER_INVALID_PASSWORD", "reason": "Too short."},
        )

    @app.post("/register-again")
    def register_again():
        raise HTTPException(
            status_code=400, detail=ErrorCode.REGISTER_USER_ALREADY_EXISTS
        )

    @app.post("/validated")
    def validated(body: Body):
        return {"value": body.value}

    @app.get("/boom")
    def boom():
        raise RuntimeError("unexpected")

    return TestClient(app, raise_server_exceptions=False)


def test_http_error_uses_the_canonical_shape(client):
    r = client.get("/forbidden")
    assert r.status_code == 403
    body = r.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == 403
    assert body["error"]["message"] == "Direct access is not permitted"
    assert body["error"]["type"] == "HTTPException"
    assert body["error"]["request_id"]


def test_one_expression_extracts_every_message(client):
    """The property the dashboard client depends on."""
    for path, expected in (("/forbidden", 403), ("/boom", 500)):
        body = client.get(path).json()
        assert body["error"]["message"], f"no message for {path}"
        assert body["error"]["code"] == expected


def test_a_fastapi_users_reason_is_the_message(client):
    """A {code, reason} detail used to arrive as a Python dict literal (#583)."""
    r = client.post("/register")
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["message"] == "Too short."
    assert body["error"]["details"] == {
        "code": "REGISTER_INVALID_PASSWORD",
        "reason": "Too short.",
    }


def test_a_fastapi_users_error_code_is_the_code_itself(client):
    """str() of the enum member read "ErrorCode.REGISTER_USER_ALREADY_EXISTS" (#589)."""
    r = client.post("/register-again")
    assert r.status_code == 400
    assert r.json()["error"]["message"] == "REGISTER_USER_ALREADY_EXISTS"


def test_validation_error_is_the_same_shape(client):
    r = client.post("/validated", json={"value": "not-an-int"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["type"] == "ValidationError"
    assert body["error"]["details"]


def test_unhandled_exception_does_not_leak_internals(client):
    r = client.get("/boom")
    assert r.status_code == 500
    assert "unexpected" not in r.text  # the detail belongs in the log, not the body
    assert r.json()["error"]["message"] == "An internal error occurred"


def test_request_id_is_taken_from_the_caller(client):
    r = client.get("/forbidden", headers={REQUEST_ID_HEADER: "trace-me-123"})
    assert r.json()["error"]["request_id"] == "trace-me-123"


# --- dict and list details (#655) -------------------------------------------
#
# The handler built the message with str(detail) and special-cased only a dict
# with a "reason". Any other dict reached the client as a Python dict literal,
# "{'error': 'Gateway authentication required', ...}", with its fields, the
# machine-readable code among them, lost. The shared gateway authentication
# dependency raises exactly such dicts, in every service that uses it.

GATEWAY_SECRET = "test-gateway-secret-at-least-32-characters"
USER_ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
TEAM_ID = "9c858901-8a57-4791-81fe-4c455b099bc9"
GATEWAY_HEADERS = {
    "X-Wildbox-User-ID": USER_ID,
    "X-Wildbox-Team-ID": TEAM_ID,
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": GATEWAY_SECRET,
}


def raising(status_code, detail, headers=None):
    """A client for an application whose GET /raise raises this detail."""
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/raise")
    def _raise():
        raise HTTPException(status_code=status_code, detail=detail, headers=headers)

    return TestClient(app, raise_server_exceptions=False)


def error_of(status_code, detail):
    response = raising(status_code, detail).get("/raise")
    assert response.status_code == status_code
    body = response.json()
    assert set(body) == {"error"}
    return body["error"]


def is_readable(message):
    """A non-empty string that is not the repr of a container."""
    return (
        isinstance(message, str)
        and bool(message.strip())
        and message.lstrip()[0] not in "{[("
    )


def test_a_dict_detail_keeps_its_message_and_its_code():
    """The acceptance case of #655."""
    detail = {"error": "E", "message": "M", "code": "C"}

    error = error_of(403, detail)

    assert error["message"] == "M"
    assert error["details"] == detail
    assert error["details"]["code"] == "C"
    # error.code stays the HTTP status; the machine-readable code is in details.
    assert error["code"] == 403
    assert error["type"] == "HTTPException"
    assert error["request_id"]


def test_a_dict_detail_without_a_message_is_not_a_dict_repr():
    error = error_of(400, {"code": "X"})

    assert error["message"] == "Bad Request"
    assert is_readable(error["message"])
    assert error["details"] == {"code": "X"}


@pytest.mark.parametrize(
    "detail, message",
    [
        ({"reason": "R", "message": "M", "error": "E"}, "R"),
        ({"message": "M", "error": "E"}, "M"),
        ({"error": "E"}, "E"),
        # A candidate that is not a non-empty string is passed over.
        ({"reason": "", "message": "M"}, "M"),
        ({"reason": "   ", "error": "E"}, "E"),
        ({"reason": None, "message": 7, "error": "E"}, "E"),
        ({"message": {"nested": "M"}, "error": ["E"]}, "Conflict"),
        ({}, "Conflict"),
    ],
)
def test_the_message_of_a_dict_detail(detail, message):
    error = error_of(409, detail)

    assert error["message"] == message
    assert error["details"] == detail


@pytest.mark.parametrize(
    "detail, details",
    [
        (["a is required", "b is not a date"], ["a is required", "b is not a date"]),
        ([{"loc": ["a"], "msg": "required"}], [{"loc": ["a"], "msg": "required"}]),
        (("a", "b"), ["a", "b"]),
        ([], []),
    ],
)
def test_a_list_detail_is_structured(detail, details):
    error = error_of(422, detail)

    assert error["message"] == "Unprocessable Entity"
    assert error["details"] == details


def test_a_set_detail_is_a_list_of_its_items():
    error = error_of(422, {"b", "a"})

    assert error["message"] == "Unprocessable Entity"
    assert sorted(error["details"]) == ["a", "b"]


class Reason(str, Enum):
    QUOTA = "QUOTA_EXCEEDED"


def test_values_json_cannot_carry_as_they_are_get_encoded():
    when = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
    identifier = uuid.UUID("3f2504e0-4f89-41d3-9a0c-0305e82c3301")

    error = error_of(
        429,
        {
            "message": "Quota exceeded",
            "code": Reason.QUOTA,
            "retry_at": when,
            "team": identifier,
            "limit": Decimal("10"),
            "scopes": {"read"},
        },
    )

    assert error["message"] == "Quota exceeded"
    assert error["details"]["code"] == "QUOTA_EXCEEDED"
    assert error["details"]["retry_at"] == when.isoformat()
    assert error["details"]["team"] == str(identifier)
    assert error["details"]["scopes"] == ["read"]
    assert float(error["details"]["limit"]) == 10.0


@pytest.mark.parametrize(
    "unencodable",
    [{"score": math.nan}, {"handle": object()}, {"n": math.inf}],
)
def test_a_detail_json_cannot_carry_keeps_its_status_and_message(unencodable):
    """It loses its details; it must not turn the endpoint's status into a 500."""
    error = error_of(403, {"message": "Not allowed", **unencodable})

    assert error["message"] == "Not allowed"
    assert "details" not in error


def test_an_enum_whose_value_is_a_dict_follows_the_dict_rule():
    class Refusal(Enum):
        LOCKED = {"message": "Account locked", "code": "LOCKED"}

    error = error_of(423, Refusal.LOCKED)

    assert error["message"] == "Account locked"
    assert error["details"] == {"message": "Account locked", "code": "LOCKED"}


@pytest.mark.parametrize(
    "detail, message",
    [
        ("", "Forbidden"),
        ("   ", "Forbidden"),
        (None, "Forbidden"),  # Starlette itself substitutes the phrase.
        (42, "42"),
        (False, "False"),
    ],
)
def test_the_message_is_never_empty(detail, message):
    error = error_of(403, detail)

    assert error["message"] == message
    assert "details" not in error


def test_a_status_without_a_standard_phrase_still_has_a_message():
    error = error_of(499, {"code": "X"})

    assert error["message"] == "Request failed"
    assert error["details"] == {"code": "X"}


def test_a_dict_detail_keeps_the_response_headers():
    response = raising(
        401,
        {"message": "Sign in", "code": "LOGIN_REQUIRED"},
        headers={"WWW-Authenticate": "Bearer"},
    ).get("/raise")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["details"]["code"] == "LOGIN_REQUIRED"


@pytest.fixture
def gateway_client(monkeypatch):
    """An application behind the real gateway authentication dependency."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", GATEWAY_SECRET)
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/items")
    def items(user=Depends(get_user_from_gateway_headers)):
        return {"team": str(user.team_id)}

    @app.delete("/items")
    def delete_items(user=Depends(require_role("owner", "admin"))):
        return {"deleted": True}

    return TestClient(app, raise_server_exceptions=False)


def without(*names):
    return {k: v for k, v in GATEWAY_HEADERS.items() if k not in names}


@pytest.mark.parametrize(
    "method, headers, status, code",
    [
        ("GET", {}, 403, "GATEWAY_AUTH_REQUIRED"),
        ("GET", without("X-Wildbox-Team-ID"), 403, "GATEWAY_AUTH_REQUIRED"),
        ("GET", without("X-Gateway-Secret"), 403, "GATEWAY_SECRET_REQUIRED"),
        (
            "GET",
            {**GATEWAY_HEADERS, "X-Gateway-Secret": "forged"},
            403,
            "GATEWAY_SECRET_REQUIRED",
        ),
        (
            "GET",
            {**GATEWAY_HEADERS, "X-Wildbox-User-ID": "not-a-uuid"},
            400,
            "INVALID_GATEWAY_HEADERS",
        ),
        (
            "GET",
            {**GATEWAY_HEADERS, "X-Wildbox-Role": "root"},
            400,
            "INVALID_GATEWAY_HEADERS",
        ),
        ("DELETE", GATEWAY_HEADERS, 403, "INSUFFICIENT_ROLE"),
    ],
)
def test_a_gateway_refusal_is_structured(gateway_client, method, headers, status, code):
    """What every service behind the shared dependency answers a refused call."""
    response = gateway_client.request(method, "/items", headers=headers)

    assert response.status_code == status
    error = response.json()["error"]
    assert error["code"] == status
    assert error["details"]["code"] == code
    assert set(error["details"]) == {"error", "message", "code"}
    # The explanation, not the title, and not a dict literal.
    assert error["message"] == error["details"]["message"]
    assert is_readable(error["message"])
    assert "{'" not in response.text


def test_a_service_without_the_gateway_secret_says_so(gateway_client, monkeypatch):
    monkeypatch.delenv("GATEWAY_INTERNAL_SECRET")

    response = gateway_client.get("/items", headers=GATEWAY_HEADERS)

    assert response.status_code == 503
    error = response.json()["error"]
    assert error["details"]["code"] == "GATEWAY_SECRET_NOT_CONFIGURED"
    assert error["message"].startswith("GATEWAY_INTERNAL_SECRET is not set")


def test_the_gateway_dependency_still_lets_a_valid_call_through(gateway_client):
    response = gateway_client.get("/items", headers=GATEWAY_HEADERS)

    assert response.status_code == 200
    assert response.json() == {"team": TEAM_ID}


# --- validation details that are not JSON as they stand -----------------------
#
# When a validator raises ValueError, pydantic keeps the exception object in
# the error's ctx. The handlers passed exc.errors() to the response as it was,
# the response could not be rendered, and input a validator refused answered
# 500 instead of 422: an IOC value of the wrong format sent to the agents
# service, for one.


class Checked(BaseModel):
    value: int

    @field_validator("value")
    @classmethod
    def not_negative(cls, value):
        if value < 0:
            raise ValueError("must not be negative")
        return value


@pytest.fixture
def checking_client():
    app = FastAPI()
    install_error_handlers(app)

    @app.post("/checked")
    def checked(body: Checked):
        return {"value": body.value}

    @app.get("/built")
    def built():
        # A model the endpoint builds itself: pydantic's own ValidationError.
        return {"value": Checked(value=-1).value}

    return TestClient(app, raise_server_exceptions=False)


def test_input_a_validator_refuses_answers_422(checking_client):
    response = checking_client.post("/checked", json={"value": -1})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["type"] == "ValidationError"
    assert error["message"] == "Request validation failed"
    [item] = error["details"]
    assert item["loc"] == ["body", "value"]
    assert "must not be negative" in item["msg"]


def test_a_model_an_endpoint_fails_to_build_answers_422(checking_client):
    response = checking_client.get("/built")

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["type"] == "ValidationError"
    assert error["message"] == "Data validation failed"
    [item] = error["details"]
    assert item["loc"] == ["value"]
    assert "must not be negative" in item["msg"]


def test_valid_input_still_passes_the_validator(checking_client):
    response = checking_client.post("/checked", json={"value": 3})

    assert response.status_code == 200
    assert response.json() == {"value": 3}
