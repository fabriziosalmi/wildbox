"""
Tests for the scope side of the shared gateway authentication dependency
(#637): what GatewayUser learns from X-Wildbox-Auth-Type and
X-Wildbox-Scopes, and require_scope, the dependency a service uses to check
again a scope the gateway already checked.

The requests go through a FastAPI application, so the headers are read the
way a service reads them. No stack is needed.
"""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from open_security_shared.gateway_auth import (
    GatewayUser,
    get_user_from_gateway_headers,
    require_scope,
)

SECRET = "test-gateway-secret-at-least-32-characters"
USER_ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
TEAM_ID = "9c858901-8a57-4791-81fe-4c455b099bc9"


@pytest.fixture(autouse=True)
def _configured_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)


def headers(auth_type=None, scopes=None, **extra):
    """The gateway's headers for a member; auth type and scopes when given."""
    result = {
        "X-Wildbox-User-ID": USER_ID,
        "X-Wildbox-Team-ID": TEAM_ID,
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": SECRET,
    }
    if auth_type is not None:
        result["X-Wildbox-Auth-Type"] = auth_type
    if scopes is not None:
        result["X-Wildbox-Scopes"] = scopes
    result.update(extra)
    return result


app = FastAPI()


@app.get("/whoami")
async def whoami(user: GatewayUser = Depends(get_user_from_gateway_headers)):
    return {"auth_type": user.auth_type, "scopes": user.scopes}


@app.post("/ingest")
async def ingest(user: GatewayUser = Depends(require_scope("data:ingest"))):
    return {"user_id": str(user.user_id), "team_id": str(user.team_id)}


by_method = require_scope(read="data:read", write="data:write", delete="data:delete")


@app.api_route("/assets", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def assets(user: GatewayUser = Depends(by_method)):
    return {"ok": True}


generic = require_scope(read="read", write="write")


@app.api_route("/sources", methods=["GET", "POST", "DELETE"])
async def sources(user: GatewayUser = Depends(generic)):
    return {"ok": True}


client = TestClient(app)


def code(response):
    return response.json()["detail"]["code"]


# --- What the user carries ---------------------------------------------------


def test_a_session_has_an_auth_type_and_no_scopes():
    body = client.get("/whoami", headers=headers("session")).json()

    assert body == {"auth_type": "session", "scopes": None}


def test_an_api_key_carries_its_scopes_in_order():
    body = client.get(
        "/whoami", headers=headers("api_key", "tools:read data:ingest data:read")
    ).json()

    assert body == {
        "auth_type": "api_key",
        "scopes": ["tools:read", "data:ingest", "data:read"],
    }


def test_without_the_headers_the_user_says_nothing_about_the_credential():
    """A route that needs no scope keeps working behind an older gateway."""
    response = client.get("/whoami", headers=headers())

    assert response.status_code == 200
    assert response.json() == {"auth_type": None, "scopes": None}


@pytest.mark.parametrize(
    "auth_type,scopes",
    [
        ("jwt", None),
        ("", None),
        ("API_KEY", "read"),
        ("api_key", ""),
        ("api_key", "read,write"),
        ("api_key", "read  write"),
        ("api_key", '["read"]'),
        ("session", "not a scope!"),
    ],
)
def test_a_malformed_auth_type_or_scope_list_is_refused_on_every_route(
    auth_type, scopes
):
    """Even where no scope is required: the gateway does not write these."""
    response = client.get("/whoami", headers=headers(auth_type, scopes))

    assert response.status_code == 400
    assert code(response) == "INVALID_GATEWAY_HEADERS"


def test_the_credential_headers_do_not_replace_the_proof_of_origin():
    forged = headers("session", **{"X-Gateway-Secret": "not-the-secret"})

    assert client.post("/ingest", headers=forged).status_code == 403
    assert code(client.post("/ingest", headers=forged)) == "GATEWAY_SECRET_REQUIRED"


@pytest.mark.asyncio
async def test_called_directly_a_header_left_out_is_absent():
    """tools' own dependency passes the headers on by keyword."""
    user = await get_user_from_gateway_headers(
        x_wildbox_user_id=USER_ID,
        x_wildbox_team_id=TEAM_ID,
        x_wildbox_role="member",
        x_gateway_secret=SECRET,
    )

    assert user.auth_type is None and user.scopes is None
    assert not user.has_scope("read")


def test_has_scope_on_a_user_built_in_code():
    session = GatewayUser(user_id=USER_ID, team_id=TEAM_ID, auth_type="session")
    key = GatewayUser(
        user_id=USER_ID, team_id=TEAM_ID, auth_type="api_key", scopes=("data:ingest",)
    )
    unstated = GatewayUser(user_id=USER_ID, team_id=TEAM_ID)

    assert session.has_scope("data:delete")
    assert key.has_scope("data:ingest") and not key.has_scope("read")
    assert not unstated.has_scope("read")


# --- require_scope: one scope ------------------------------------------------


def test_a_session_passes():
    response = client.post("/ingest", headers=headers("session"))

    assert response.status_code == 200
    assert response.json() == {"user_id": USER_ID, "team_id": TEAM_ID}


def test_a_service_calling_for_a_user_passes():
    assert client.post("/ingest", headers=headers("service")).status_code == 200


@pytest.mark.parametrize(
    "scopes", ["data:ingest", "data:write", "write", "admin", "*", "read data:ingest"]
)
def test_a_key_with_a_scope_that_satisfies_passes(scopes):
    assert client.post("/ingest", headers=headers("api_key", scopes)).status_code == 200


@pytest.mark.parametrize(
    "scopes",
    ["read", "data:read", "data:delete", "tools:execute", "tools:admin", "team:manage"],
)
def test_a_key_without_the_scope_is_refused(scopes):
    response = client.post("/ingest", headers=headers("api_key", scopes))

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["code"] == "INSUFFICIENT_SCOPE"
    assert detail["error"] == "insufficient_scope"
    assert detail["required_scope"] == "data:ingest"


def test_a_key_with_no_scopes_header_is_refused():
    response = client.post("/ingest", headers=headers("api_key"))

    assert response.status_code == 403
    assert code(response) == "INSUFFICIENT_SCOPE"


def test_a_request_that_does_not_state_the_auth_type_is_refused():
    """An older gateway, or a caller holding the secret that does not say."""
    response = client.post("/ingest", headers=headers())

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["code"] == "GATEWAY_AUTH_TYPE_REQUIRED"
    assert detail["required_scope"] == "data:ingest"


def test_scopes_without_an_auth_type_are_not_enough():
    response = client.post("/ingest", headers=headers(None, "*"))

    assert response.status_code == 403
    assert code(response) == "GATEWAY_AUTH_TYPE_REQUIRED"


def test_a_direct_request_is_refused_before_any_scope_is_read():
    response = client.post(
        "/ingest", headers={"X-Wildbox-Auth-Type": "session", "X-Wildbox-Scopes": "*"}
    )

    assert response.status_code == 403
    assert code(response) == "GATEWAY_AUTH_REQUIRED"


# --- require_scope: by method ------------------------------------------------


@pytest.mark.parametrize(
    "method,scopes,allowed",
    [
        ("GET", "data:read", True),
        ("HEAD", "data:read", True),
        ("GET", "data:ingest", False),
        ("POST", "data:read", False),
        ("POST", "data:write", True),
        ("PUT", "data:write", True),
        ("PATCH", "data:read", False),
        ("DELETE", "data:write", False),
        ("DELETE", "write", False),
        ("DELETE", "data:delete", True),
        ("GET", "data:delete", False),
        ("DELETE", "admin", True),
    ],
)
def test_the_scope_follows_the_method(method, scopes, allowed):
    response = client.request(method, "/assets", headers=headers("api_key", scopes))

    assert response.status_code == (200 if allowed else 403)


def test_the_refusal_names_the_scope_the_method_needed():
    response = client.delete("/assets", headers=headers("api_key", "data:write"))

    assert response.json()["detail"]["required_scope"] == "data:delete"


def test_the_sensor_key_is_refused_on_a_service_generic_routes():
    """data:ingest reads and writes nothing else in the data service."""
    assert (
        client.get("/sources", headers=headers("api_key", "data:ingest")).status_code
        == 403
    )
    assert (
        client.post("/sources", headers=headers("api_key", "data:ingest")).status_code
        == 403
    )
    assert client.get("/sources", headers=headers("api_key", "read")).status_code == 200
    assert (
        client.post("/sources", headers=headers("api_key", "read")).status_code == 403
    )
    # No delete scope named: DELETE is a write.
    assert (
        client.delete("/sources", headers=headers("api_key", "write")).status_code
        == 200
    )
    assert client.get("/sources", headers=headers("session")).status_code == 200


# --- require_scope: its own arguments ----------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"read": "read"},
        {"write": "write"},
        {"delete": "data:delete"},
        {"required": "data:ingest", "read": "read", "write": "write"},
    ],
)
def test_require_scope_refuses_arguments_that_name_no_complete_rule(kwargs):
    with pytest.raises(ValueError):
        require_scope(**kwargs)


def test_require_scope_checks_the_user_a_service_dependency_returns():
    """tools wraps the shared dependency; the scope is checked on its user."""

    async def service_user():
        return GatewayUser(
            user_id=USER_ID,
            team_id=TEAM_ID,
            auth_type="api_key",
            scopes=("tools:read",),
        )

    wrapped = FastAPI()

    @wrapped.post("/run")
    async def run(
        user: GatewayUser = Depends(
            require_scope("tools:execute", user_dependency=service_user)
        )
    ):
        return {"ok": True}

    @wrapped.get("/list")
    async def listing(
        user: GatewayUser = Depends(
            require_scope("tools:read", user_dependency=service_user)
        )
    ):
        return {"ok": True}

    wrapped_client = TestClient(wrapped)

    assert wrapped_client.post("/run").status_code == 403
    assert wrapped_client.get("/list").status_code == 200
