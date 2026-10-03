"""The tools service no longer serves its standalone web UI (#581).

The UI (``app/web``: an index page, a page per tool, settings, a developer
guide, Swagger UI and ReDoc pages, and ``/static``) did not work through the
gateway, and the dashboard's ``/toolbox`` replaces it. These tests pin that
none of its routes is registered any more while the JSON API still is.
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


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/tools/hash_generator",
        "/settings",
        "/guide",
        "/docs",
        "/redoc",
        "/static/css/styles.css",
        "/static/js/script.js",
    ],
)
def test_web_ui_paths_are_not_served(app, path):
    # No lifespan: building the app is enough to know its routes.
    response = TestClient(app).get(path)

    assert response.status_code == 404, path


def test_the_schema_lists_the_api_and_no_web_page(app):
    paths = TestClient(app).get("/openapi.json").json()["paths"]

    assert "/api/tools" in paths
    assert "/api/tools/{tool_name}/info" in paths
    assert "/" not in paths
    assert "/tools/{tool_name}" not in paths


def test_the_json_api_still_answers(app):
    # 401, not 404: the route exists and asks for the gateway's identity.
    response = TestClient(app).get("/api/tools")

    assert response.status_code == 401
