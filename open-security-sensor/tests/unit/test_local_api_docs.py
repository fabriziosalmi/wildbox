"""The sensor's local API lists its routes in development only (#722).

``GET /`` and ``GET /docs`` answer an HTML page that names every route of the
local API, without authentication. The condition was "ENVIRONMENT is not
production", with a missing variable read as ``development``: the sensor's
Compose files set no ENVIRONMENT, so the page was served wherever the sensor
ran. The rule is now the one of the platform's services
(``open-security-shared/api_docs.py``): the environment must say
``development``, and one that is not declared does not.
"""

import sys
from pathlib import Path

import pytest
from aiohttp import web

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.api.local_api import LocalAPI  # noqa: E402

DOCUMENTATION = {"/", "/docs"}


def get_routes(monkeypatch, environment):
    """Paths the local API serves with GET under ENVIRONMENT=environment.

    ``None`` builds the routes without the variable.
    """
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    if environment is not None:
        monkeypatch.setenv("ENVIRONMENT", environment)
    api = LocalAPI(config=None, agent=None)
    api.app = web.Application()
    api._setup_routes()
    return {
        route.resource.canonical
        for route in api.app.router.routes()
        if route.method == "GET"
    }


@pytest.mark.parametrize("environment", [None, "", "  ", "production", "staging"])
def test_the_route_list_is_not_served_outside_development(monkeypatch, environment):
    routes = get_routes(monkeypatch, environment)
    assert not DOCUMENTATION & routes
    # The API itself is there: only the page that describes it is not.
    assert {"/health", "/api/v1/status", "/api/v1/config"} <= routes


@pytest.mark.parametrize("environment", ["development", "Development", " development "])
def test_the_route_list_is_served_in_development(monkeypatch, environment):
    assert DOCUMENTATION <= get_routes(monkeypatch, environment)


def test_the_readme_states_the_rule():
    readme = (SERVICE_ROOT / "README.md").read_text(encoding="utf-8")
    assert "only when `ENVIRONMENT=development`" in " ".join(readme.split())
    assert "`ENVIRONMENT=production` disables" not in readme
