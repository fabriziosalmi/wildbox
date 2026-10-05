"""The routes of the tools service that are not tool or task routes (#646).

``/metrics`` (Prometheus) and ``/health`` are what the deployment probes;
this module pins which of them exist and what they answer.
"""

import os
import re
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.main import create_app  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return create_app()


@pytest.fixture
def client(app):
    # No lifespan: building the app is enough to know its routes.
    return TestClient(app, raise_server_exceptions=False)


def _get_routes(app, path):
    return [
        route
        for route in app.routes
        if getattr(route, "path", None) == path and "GET" in route.methods
    ]


# --- /metrics --------------------------------------------------------------


def test_metrics_is_the_prometheus_endpoint_of_the_shared_package(app, client):
    client.get("/api/tools")  # one request, so the counter has a sample

    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "# TYPE wildbox_http_requests_total counter" in body
    assert 'path="/api/tools",service="tools",status="401"' in body
    # The execution counter the alert rules read (monitoring/alert_rules.yml).
    assert "# TYPE wildbox_tool_executions_total counter" in body
    assert len(_get_routes(app, "/metrics")) == 1


def test_the_json_metrics_route_that_always_failed_is_gone(client):
    # It imported app.middleware.metrics_middleware, which does not exist,
    # and answered 500 to every request.
    response = client.get("/api/system/metrics")

    assert response.status_code == 404


# --- /health ---------------------------------------------------------------


def test_exactly_one_health_route_is_registered(app):
    # Two handlers used to be registered for GET /health. The second, the
    # one documented "for Docker and monitoring", never answered.
    assert len(_get_routes(app, "/health")) == 1


def test_health_answers_what_the_probes_read(client):
    # compose and the image probe it with `curl -f`: any 2xx is healthy.
    # tests/integration/test_ci_integration.py reads `status`.
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["service"] == "tools"
    assert body["tools_count"] == len(body["available_tools"]) > 0
    # The fields of the handler that never ran are not part of the answer.
    assert "uptime_seconds" not in body
    assert "tools_loaded" not in body


# --- /api/system/* ---------------------------------------------------------

# The four routes that used to answer anyone who could reach the service
# port, with the environment, the debug flag, execution counters and the
# health body of every other service.
REMOVED_SYSTEM_PATHS = [
    "/api/system/info",
    "/api/system/metrics",
    "/api/system/operational-metrics",
    "/api/system/health-aggregate",
]

GATEWAY_SECRET = "unit-test-gateway-proof-0123456789"

# Routes that answer without the gateway's identity, on purpose: the health
# probe, the Prometheus scrape, the schema and the service banner.
OPEN_PATHS = {"/health", "/metrics", "/openapi.json", "/api"}


def _gateway_headers(role):
    return {
        "X-Wildbox-User-ID": str(uuid.uuid4()),
        "X-Wildbox-Team-ID": str(uuid.uuid4()),
        "X-Wildbox-Role": role,
        "X-Gateway-Secret": GATEWAY_SECRET,
    }


@pytest.mark.parametrize("path", REMOVED_SYSTEM_PATHS)
def test_a_system_route_does_not_answer_an_anonymous_caller(client, path):
    response = client.get(path)

    assert response.status_code == 404, path


@pytest.mark.parametrize("path", REMOVED_SYSTEM_PATHS)
@pytest.mark.parametrize("role", ["owner", "admin", "member"])
def test_a_system_route_does_not_answer_a_gateway_caller(
    client, monkeypatch, path, role
):
    # Removed, not hidden behind a role: a team role says nothing about who
    # may read platform-wide data, and anyone who registers owns a team.
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", GATEWAY_SECRET)

    response = client.get(path, headers=_gateway_headers(role))

    assert response.status_code == 404, (path, role)


def test_the_schema_lists_no_system_route(app):
    assert [path for path in app.openapi()["paths"] if "system" in path] == []


def test_every_api_route_asks_for_the_gateway_identity(app, client):
    """No route under /api/ answers a caller the gateway did not vouch for.

    Every operation in the schema is called without credentials. A new route
    registered without the ``get_current_user`` dependency fails here.
    """
    operations = [
        (method.upper(), re.sub(r"\{[^}]+\}", "x", path))
        for path, item in app.openapi()["paths"].items()
        if path not in OPEN_PATHS
        for method in item
    ]
    # The enumeration reaches the tool list, a run endpoint per tool, the
    # asynchronous submission and the task routes; nothing else is left.
    assert {
        ("GET", "/api/tools"),
        ("POST", "/api/tools/hash_generator"),
        ("POST", "/api/tools/x/async"),
        ("GET", "/api/tasks"),
        ("DELETE", "/api/tasks/x"),
    } <= set(operations)
    assert all(path.startswith("/api/") for _, path in operations)

    answered = [
        (method, path, response.status_code)
        for method, path in operations
        for response in [client.request(method, path)]
        if response.status_code != 401
    ]

    assert answered == []


def test_the_settings_of_the_health_aggregate_are_gone():
    # Seven optional URLs that only /api/system/health-aggregate read.
    from app.config import Settings

    assert [
        name for name in Settings.model_fields if name.endswith("_service_url")
    ] == []
