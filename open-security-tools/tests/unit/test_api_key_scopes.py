"""The tools service checks tools:execute itself (#637).

The gateway requires tools:execute of an API key that runs a tool or cancels
a task, and tools:read of one that lists and reads. It used to be the only
check: the service was told who the caller was, not what the credential was
allowed, so a mistake in the gateway's scope map (one was found in #647)
would have let a read-only key run tools with nothing behind it.

The gateway now forwards the credential's type and an API key's scopes, and
the routes that run a tool or cancel a task depend on require_tools_execute.
These tests send requests as the gateway forwards them, with no
authentication override.
"""

import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.api import router as router_module  # noqa: E402
from app.auth import require_tools_execute, verify_api_key  # noqa: E402
from app.tool_loader import load_tool_module  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SECRET = "unit-test-gateway-secret-0123456789"
USER_ID = str(uuid.uuid4())
TEAM_ID = str(uuid.uuid4())
TOOL = "hash_generator"
RUN = f"/api/tools/{TOOL}"
INPUT = {"input_text": "wildbox"}


def gateway(auth_type=None, scopes=None):
    """The headers the gateway forwards for a member."""
    headers = {
        "X-Wildbox-User-ID": USER_ID,
        "X-Wildbox-Team-ID": TEAM_ID,
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": SECRET,
    }
    if auth_type is not None:
        headers["X-Wildbox-Auth-Type"] = auth_type
    if scopes is not None:
        headers["X-Wildbox-Scopes"] = scopes
    return headers


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    if not any(getattr(r, "path", "") == RUN for r in router_module.router.routes):
        router_module.register_tool_endpoint(None, TOOL, load_tool_module(TOOL))
    router_module.DISCOVERED_TOOLS.setdefault(TOOL, load_tool_module(TOOL))
    app = FastAPI()
    app.include_router(router_module.router)
    return TestClient(app, raise_server_exceptions=False)


def depends_on(route, dependency):
    return any(sub.call is dependency for sub in route.dependant.dependencies)


# --- Running a tool ----------------------------------------------------------


def test_a_session_runs_a_tool(client):
    response = client.post(RUN, json=INPUT, headers=gateway("session"))

    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "scopes",
    ["tools:execute", "tools:admin", "write", "admin", "*", "tools:read tools:execute"],
)
def test_a_key_that_may_execute_runs_a_tool(client, scopes):
    """What satisfied the route at the gateway before still does."""
    response = client.post(RUN, json=INPUT, headers=gateway("api_key", scopes))

    assert response.status_code == 200, response.text


def test_a_service_calling_for_a_user_runs_a_tool(client):
    """The agents service and the responder call tools with the gateway secret."""
    assert client.post(RUN, json=INPUT, headers=gateway("service")).status_code == 200


@pytest.mark.parametrize(
    "scopes",
    ["tools:read", "read", "data:write", "data:ingest", "data:read tools:read"],
)
def test_a_key_that_may_not_execute_does_not_run_a_tool(client, scopes, monkeypatch):
    ran = []
    monkeypatch.setattr(
        router_module.execution_manager,
        "execute_tool",
        lambda *a, **k: ran.append(a) or None,
    )

    response = client.post(RUN, json=INPUT, headers=gateway("api_key", scopes))

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["code"] == "INSUFFICIENT_SCOPE"
    assert detail["required_scope"] == "tools:execute"
    assert ran == []


def test_a_key_with_no_scopes_does_not_run_a_tool(client):
    response = client.post(RUN, json=INPUT, headers=gateway("api_key"))

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "INSUFFICIENT_SCOPE"


def test_a_request_that_does_not_state_its_credential_does_not_run_a_tool(client):
    """A gateway from before these headers."""
    response = client.post(RUN, json=INPUT, headers=gateway())

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "GATEWAY_AUTH_TYPE_REQUIRED"


def test_a_malformed_scope_list_is_refused(client):
    response = client.post(
        RUN, json=INPUT, headers=gateway("api_key", "tools:execute,write")
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_GATEWAY_HEADERS"


def test_a_direct_request_is_still_401(client):
    """The scope dependency sits behind the service's own authentication."""
    response = client.post(RUN, json=INPUT, headers={"X-Wildbox-Auth-Type": "session"})

    assert response.status_code == 401


# --- Reading is unchanged ----------------------------------------------------


@pytest.mark.parametrize(
    "headers", [gateway("api_key", "tools:read"), gateway("session"), gateway()]
)
def test_listing_and_reading_tools_need_no_scope_here(client, headers):
    """The gateway requires tools:read; the service does not check it again."""
    assert client.get("/api/tools", headers=headers).status_code == 200
    assert client.get(f"{RUN}/info", headers=headers).status_code == 200


# --- Every route that runs or cancels ----------------------------------------


def _routes():
    from app.api import async_router

    return [
        route
        for router in (router_module.router, async_router.router)
        for route in router.routes
        if isinstance(route, APIRoute)
    ]


def test_every_route_that_is_not_a_read_requires_tools_execute(client):
    """A tool endpoint or a task route added without the dependency fails here."""
    pytest.importorskip("celery")
    changing = [r for r in _routes() if r.methods - {"GET", "HEAD", "OPTIONS"}]

    assert {r.path for r in changing} >= {
        RUN,
        "/api/tools/{tool_name}/async",
        "/api/tasks/{task_id}",
    }
    for route in changing:
        assert depends_on(
            route, require_tools_execute
        ), f"{sorted(route.methods)} {route.path}"


def test_the_read_routes_authenticate_without_a_scope(client):
    pytest.importorskip("celery")
    reading = [r for r in _routes() if not r.methods - {"GET", "HEAD", "OPTIONS"}]

    assert {r.path for r in reading} >= {
        "/api/tools",
        "/api/tools/{tool_name}/info",
        "/api/tasks",
        "/api/tasks/{task_id}",
    }
    for route in reading:
        assert depends_on(route, verify_api_key), route.path
        assert not depends_on(route, require_tools_execute), route.path


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", f"/api/tools/{TOOL}/async"),
        ("DELETE", "/api/tasks/1f0c4ea6-0000-4000-8000-000000000000"),
    ],
)
def test_a_read_only_key_neither_submits_nor_cancels_a_task(monkeypatch, method, path):
    pytest.importorskip("celery")
    from app.api import async_router

    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    app = FastAPI()
    app.include_router(async_router.router)
    api = TestClient(app, raise_server_exceptions=False)

    response = api.request(
        method, path, json=INPUT, headers=gateway("api_key", "tools:read")
    )

    assert response.status_code == 403
    assert response.json()["detail"]["required_scope"] == "tools:execute"

    response = api.request(method, path, json=INPUT, headers=gateway())

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "GATEWAY_AUTH_TYPE_REQUIRED"
