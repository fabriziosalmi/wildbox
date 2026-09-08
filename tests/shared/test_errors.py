"""
Tests for the canonical error contract.

Four incompatible error shapes used to be served under one API, and the
dashboard's client read a field three of them did not have, so most server
explanations never reached a user (WILDBO-API-01/API-02). These tests pin the
one shape every service now installs.
"""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from open_security_shared.errors import REQUEST_ID_HEADER, install_error_handlers
from pydantic import BaseModel


class Body(BaseModel):
    value: int


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
