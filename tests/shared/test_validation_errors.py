"""A validation error says where and what, and does not repeat what was sent (#722).

FastAPI's list of validation errors carries, for each error, the ``input``
that was refused. The shared handlers returned the list as it was, so a 422
handed the request back to the caller: for a missing field, ``input`` is the
whole object the field is missing from, every sibling field included. A login
form posted without its email returned the password. A client that logs the
error bodies it receives, as clients do, then keeps the secret in a log.

The contract is the one the tools service already had for tool input: each
item of ``error.details`` is ``{"type", "loc", "msg"}`` and nothing else. No
``input``, no ``ctx`` (it can hold the input too, and, for a custom validator,
an exception object that is not JSON), no ``url``.
"""

from typing import Literal, Optional, Union

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from open_security_shared.errors import field_errors, install_error_handlers
from pydantic import BaseModel, Field, field_validator

PASSWORD = "hunter2-is-a-secret"


class Cat(BaseModel):
    kind: Literal["cat"]


class Dog(BaseModel):
    kind: Literal["dog"]


class Login(BaseModel):
    email: str
    password: str = Field(min_length=12)
    pet: Optional[Union[Cat, Dog]] = Field(default=None, discriminator="kind")
    role: Literal["admin", "member"] = "member"

    @field_validator("email")
    @classmethod
    def has_an_at_sign(cls, value):
        if "@" not in value:
            raise ValueError("must contain @")
        return value


class Row(BaseModel):
    """A model an endpoint builds from its own data, not from the request."""

    token: str
    count: int


@pytest.fixture
def client():
    app = FastAPI()
    install_error_handlers(app)

    @app.post("/login")
    def login(body: Login):
        return {"ok": True}

    @app.get("/items/{item_id}")
    def item(item_id: int, limit: int = 10):
        return {"item": item_id, "limit": limit}

    @app.get("/row")
    def row():
        # pydantic's own ValidationError: the input is the server's data.
        return Row(token="server-side-token-9f3a", count="not-a-number")

    return TestClient(app, raise_server_exceptions=False)


def details(response):
    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["type"] == "ValidationError"
    return error["details"]


def test_a_missing_field_does_not_return_its_siblings(client):
    # The case of the issue: `input` of a "missing" error is the whole body.
    response = client.post("/login", json={"password": PASSWORD})

    assert details(response) == [
        {"type": "missing", "loc": ["body", "email"], "msg": "Field required"}
    ]
    assert PASSWORD not in response.text


def test_a_refused_value_is_not_returned(client):
    response = client.post(
        "/login", json={"email": "a@example.com", "password": "pw-secret"}
    )

    assert details(response) == [
        {
            "type": "string_too_short",
            "loc": ["body", "password"],
            "msg": "String should have at least 12 characters",
        }
    ]
    assert "pw-secret" not in response.text


def test_every_item_is_a_location_a_message_and_a_type(client):
    sent = {
        "email": "email-secret",
        "password": PASSWORD,
        "pet": {"kind": "tag-secret"},
        "role": "role-secret",
    }
    response = client.post("/login", json=sent)

    items = details(response)
    assert [item["loc"] for item in items] == [
        ["body", "email"],
        ["body", "pet"],
        ["body", "role"],
    ]
    for item in items:
        assert set(item) == {"type", "loc", "msg"}
        assert isinstance(item["msg"], str) and item["msg"]
    for value in ("email-secret", PASSWORD, "tag-secret", "role-secret"):
        assert value not in response.text


def test_the_message_of_a_validator_is_kept(client):
    response = client.post("/login", json={"email": "nobody", "password": PASSWORD})

    [item] = details(response)
    assert item == {
        "type": "value_error",
        "loc": ["body", "email"],
        "msg": "Value error, must contain @",
    }


def test_the_message_for_a_union_names_the_tags_it_accepts_not_the_one_it_got(client):
    # pydantic's sentence for a discriminated union quotes the tag it was
    # given: the one stock message that repeats the input.
    response = client.post(
        "/login",
        json={
            "email": "a@example.com",
            "password": PASSWORD,
            "pet": {"kind": "tag-secret"},
        },
    )

    [item] = details(response)
    assert item["type"] == "union_tag_invalid" and item["loc"] == ["body", "pet"]
    assert "'cat', 'dog'" in item["msg"] and "'kind'" in item["msg"]
    assert "tag-secret" not in response.text


def test_path_and_query_values_are_not_returned(client):
    response = client.get("/items/path-secret?limit=query-secret")

    assert [(item["loc"], item["type"]) for item in details(response)] == [
        (["path", "item_id"], "int_parsing"),
        (["query", "limit"], "int_parsing"),
    ]
    assert "path-secret" not in response.text
    assert "query-secret" not in response.text


def test_a_body_that_is_not_json_is_not_returned(client):
    response = client.post(
        "/login",
        content=b'{"password": "json-secret", ',
        headers={"Content-Type": "application/json"},
    )

    [item] = details(response)
    assert item["type"] == "json_invalid" and item["loc"][0] == "body"
    assert item["msg"] == "JSON decode error"
    assert set(item) == {"type", "loc", "msg"}
    assert "json-secret" not in response.text


def test_a_model_the_endpoint_builds_does_not_return_the_data_it_was_built_from(client):
    response = client.get("/row")

    assert response.json()["error"]["message"] == "Data validation failed"
    [item] = details(response)
    assert item["loc"] == ["count"] and item["type"] == "int_parsing"
    assert set(item) == {"type", "loc", "msg"}
    assert "server-side-token" not in response.text
    assert "not-a-number" not in response.text


def test_valid_input_still_passes(client):
    response = client.post(
        "/login", json={"email": "a@example.com", "password": PASSWORD}
    )

    assert response.status_code == 200


# --- field_errors itself -----------------------------------------------------


def test_field_errors_keeps_three_keys_of_what_pydantic_reports():
    reported = [
        {
            "type": "string_too_short",
            "loc": ("body", "password"),
            "msg": "String should have at least 12 characters",
            "input": "pw-secret",
            "ctx": {"min_length": 12},
            "url": "https://errors.pydantic.dev/2/v/string_too_short",
        }
    ]

    assert field_errors(reported) == [
        {
            "type": "string_too_short",
            "loc": ["body", "password"],
            "msg": "String should have at least 12 characters",
        }
    ]


def test_field_errors_drops_a_context_that_is_not_json():
    # A validator that raises: pydantic keeps the exception in ctx.error.
    reported = [
        {
            "type": "value_error",
            "loc": ("body", "email"),
            "msg": "Value error, must contain @",
            "input": "nobody",
            "ctx": {"error": ValueError("must contain @")},
        }
    ]

    assert field_errors(reported) == [
        {
            "type": "value_error",
            "loc": ["body", "email"],
            "msg": "Value error, must contain @",
        }
    ]


@pytest.mark.parametrize(
    "context, message",
    [
        (
            {
                "discriminator": "'kind'",
                "tag": "tag-secret",
                "expected_tags": "'cat', 'dog'",
            },
            "Input tag found using 'kind' does not match any of the expected tags: 'cat', 'dog'",
        ),
        ({"tag": "tag-secret"}, "Input tag does not match any of the expected tags"),
        (None, "Input tag does not match any of the expected tags"),
    ],
)
def test_field_errors_rewrites_the_one_message_that_quotes_the_input(context, message):
    reported = {
        "type": "union_tag_invalid",
        "loc": ("body", "pet"),
        "msg": "Input tag 'tag-secret' found using 'kind' does not match any of the "
        "expected tags: 'cat', 'dog'",
        "input": {"kind": "tag-secret"},
    }
    if context is not None:
        reported["ctx"] = context

    assert field_errors([reported]) == [
        {"type": "union_tag_invalid", "loc": ["body", "pet"], "msg": message}
    ]


def test_field_errors_survives_what_it_does_not_expect():
    assert field_errors([]) == []
    assert field_errors(None) == []
    assert field_errors(["not a mapping", {"msg": "only a message"}]) == [
        {"msg": "only a message"}
    ]
