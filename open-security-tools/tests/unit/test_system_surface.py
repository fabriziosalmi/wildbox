"""The routes of the tools service that are not tool or task routes (#646).

``/metrics`` (Prometheus) and ``/health`` are what the deployment probes;
this module pins which of them exist and what they answer.
"""

import os
import sys

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
